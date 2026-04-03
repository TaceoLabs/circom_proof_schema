use ark_circom::circom::R1CSFile;
use ark_ec::pairing::Pairing;
use ark_ff::Zero;
use ark_groth16::Proof;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::{ConstraintMatrices, SynthesisError};
use co_circom::{
    CircomArkworksPairingBridge, CoCircomCompiler, CoCircomCompilerParsed, CompilerConfig,
    ProvingKey,
};

use eyre::Context;
use rand::{CryptoRng, Rng};
use std::{fs::File, path::PathBuf};

use crate::proving_key::QapReduction;

pub struct CircomProofSchema<P: Pairing> {
    pub pk: ProvingKey<P>,
    pub matrices: ConstraintMatrices<P::ScalarField>,
}

impl<P: Pairing> CircomProofSchema<P>
where
    P: CircomArkworksPairingBridge,
{
    fn get_compiler_config(link_lib: PathBuf) -> CompilerConfig {
        let mut compiler = CompilerConfig::release();
        compiler.link_library = vec![link_lib];
        compiler
    }

    #[must_use]
    pub const fn size(&self) -> (usize, usize) {
        (
            self.matrices.num_constraints,
            self.matrices.num_witness_variables,
        )
    }

    pub fn read_circuit_co_circom(
        path: PathBuf,
        link_lib: PathBuf,
    ) -> eyre::Result<CoCircomCompilerParsed<P::ScalarField>> {
        let compiler_config = Self::get_compiler_config(link_lib);
        CoCircomCompiler::<P>::parse(path, compiler_config).context("while parsing circuit file")
    }

    fn rc1s_to_constraint_matrix(
        r1cs: R1CSFile<P::ScalarField>,
    ) -> ConstraintMatrices<P::ScalarField> {
        let num_constraints = r1cs.header.n_constraints as usize;
        let num_public_inputs = r1cs.header.n_pub_in as usize + r1cs.header.n_pub_out as usize + 1;
        let num_witnesses = r1cs.header.n_wires as usize;
        let mut a_num_non_zero = 0;
        let mut b_num_non_zero = 0;
        let mut c_num_non_zero = 0;

        debug_assert_eq!(num_constraints, r1cs.constraints.len());
        let mut a = vec![Vec::new(); num_constraints];
        let mut b = vec![Vec::new(); num_constraints];
        let mut c = vec![Vec::new(); num_constraints];

        for (row, constraints) in r1cs.constraints.into_iter().enumerate() {
            let (a_, b_, c_) = constraints;
            for (col, val) in a_ {
                if val.is_zero() {
                    continue;
                }
                a_num_non_zero += 1;
                a[row].push((val, col));
            }

            for (col, val) in b_ {
                if val.is_zero() {
                    continue;
                }
                b_num_non_zero += 1;
                b[row].push((val, col));
            }

            for (col, val) in c_ {
                if val.is_zero() {
                    continue;
                }
                c_num_non_zero += 1;
                c[row].push((val, col));
            }
        }

        ConstraintMatrices {
            num_instance_variables: num_public_inputs,
            num_witness_variables: num_witnesses - num_public_inputs,
            num_constraints,
            a_num_non_zero,
            b_num_non_zero,
            c_num_non_zero,
            a,
            b,
            c,
        }
    }

    pub fn from_r1cs_libsnark<R: Rng + CryptoRng>(
        r1cs: R1CSFile<P::ScalarField>,
        rng: &mut R,
    ) -> eyre::Result<Self> {
        let matrices = Self::rc1s_to_constraint_matrix(r1cs);
        let pk = Self::generate_proving_key_libsnark(rng, &matrices)?;
        Ok(Self { pk, matrices })
    }

    pub fn from_r1cs_file_libsnark<R: Rng + CryptoRng>(
        path: PathBuf,
        rng: &mut R,
    ) -> eyre::Result<Self> {
        let file = File::open(path)?;
        let r1cs = R1CSFile::<P::ScalarField>::new(file).context("while reading r1cs file")?;
        Self::from_r1cs_libsnark(r1cs, rng)
    }

    pub fn from_r1cs_circom<R: Rng + CryptoRng>(
        r1cs: R1CSFile<P::ScalarField>,
        rng: &mut R,
    ) -> eyre::Result<Self> {
        let matrices = Self::rc1s_to_constraint_matrix(r1cs);
        let pk = Self::generate_proving_key_circom(rng, &matrices)?;
        Ok(Self { pk, matrices })
    }

    pub fn from_r1cs_file_circom<R: Rng + CryptoRng>(
        path: PathBuf,
        rng: &mut R,
    ) -> eyre::Result<Self> {
        let file = File::open(path)?;
        let r1cs = R1CSFile::<P::ScalarField>::new(file).context("while reading r1cs file")?;
        Self::from_r1cs_circom(r1cs, rng)
    }

    // This is extracted from ark-groth (generate_random_parameters_with_reduction)
    // TODO make a ceremnoy out of this
    pub fn generate_proving_key_libsnark<R: Rng + CryptoRng>(
        rng: &mut R,
        matrices: &ConstraintMatrices<P::ScalarField>,
    ) -> eyre::Result<ProvingKey<P>> {
        type D<F> = GeneralEvaluationDomain<F>;

        let domain_size = matrices.num_constraints + matrices.num_instance_variables;
        let domain = D::<P::ScalarField>::new(domain_size)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let t = domain.sample_element_outside_domain(rng);

        let qap = Self::qap_reduction::<D<P::ScalarField>>(t, matrices)?;
        crate::proving_key::generate_proving_key_libsnark(
            rng,
            t,
            matrices.num_instance_variables,
            qap,
        )
    }

    // This is extracted from ark-groth (generate_random_parameters_with_reduction)
    // TODO make a ceremnoy out of this
    pub fn generate_proving_key_circom<R: Rng + CryptoRng>(
        rng: &mut R,
        matrices: &ConstraintMatrices<P::ScalarField>,
    ) -> eyre::Result<ProvingKey<P>> {
        type D<F> = GeneralEvaluationDomain<F>;

        let domain_size = matrices.num_constraints + matrices.num_instance_variables;
        let domain = D::<P::ScalarField>::new(domain_size)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let t = domain.sample_element_outside_domain(rng);

        let qap = Self::qap_reduction::<D<P::ScalarField>>(t, matrices)?;
        crate::proving_key::generate_proving_key_circom(
            rng,
            t,
            matrices.num_instance_variables,
            qap,
        )
    }

    // Copied from ark-groth16 (instance_map_with_evaluation)
    fn qap_reduction<D: EvaluationDomain<P::ScalarField>>(
        t: P::ScalarField,
        matrices: &ConstraintMatrices<P::ScalarField>,
    ) -> eyre::Result<QapReduction<P::ScalarField>> {
        let domain_size = matrices.num_constraints + matrices.num_instance_variables;
        let domain = D::new(domain_size).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let domain_size = domain.size();

        let zt = domain.evaluate_vanishing_polynomial(t);

        // Evaluate all Lagrange polynomials

        let u = domain.evaluate_all_lagrange_coefficients(t);

        let qap_num_variables =
            matrices.num_witness_variables + matrices.num_instance_variables - 1;

        let mut a = vec![P::ScalarField::zero(); qap_num_variables + 1];
        let mut b = vec![P::ScalarField::zero(); qap_num_variables + 1];
        let mut c = vec![P::ScalarField::zero(); qap_num_variables + 1];

        {
            let start = 0;
            let end = matrices.num_instance_variables;
            let num_constraints = matrices.num_constraints;
            a[start..end].copy_from_slice(&u[(start + num_constraints)..(end + num_constraints)]);
        }

        for (i, u_i) in u.iter().enumerate().take(matrices.num_constraints) {
            for (coeff, index) in matrices.a[i].iter() {
                a[*index] += &(*u_i * coeff);
            }
            for (coeff, index) in matrices.b[i].iter() {
                b[*index] += &(*u_i * coeff);
            }
            for (coeff, index) in matrices.c[i].iter() {
                c[*index] += &(*u_i * coeff);
            }
        }

        Ok(QapReduction {
            a,
            b,
            c,
            zt,
            qap_num_variables,
            m_raw: domain_size,
        })
    }

    pub fn verify(&self, proof: &Proof<P>, public_inputs: &[P::ScalarField]) -> eyre::Result<bool> {
        let vk = ark_groth16::prepare_verifying_key(&self.pk.vk);
        let proof_valid = ark_groth16::Groth16::<P>::verify_proof(&vk, proof, public_inputs)
            .map_err(eyre::Report::from)?;
        Ok(proof_valid)
    }
}
