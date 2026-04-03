pub mod proof_schema;
pub mod proving_key;

use ark_ff::PrimeField;
use ark_poly::EvaluationDomain;
use ark_relations::r1cs::SynthesisError;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};

pub(crate) fn h_query_scalars_libsnark<F: PrimeField>(
    max_power: usize,
    t: F,
    zt: F,
    delta_inverse: F,
) -> Result<Vec<F>, SynthesisError> {
    let scalars = (0..max_power)
        .map(|i| zt * delta_inverse * t.pow([i as u64]))
        .collect::<Vec<_>>();
    Ok(scalars)
}

pub(crate) fn h_query_scalars_circom<F: PrimeField, D: EvaluationDomain<F>>(
    max_power: usize,
    t: F,
    _: F,
    delta_inverse: F,
) -> Result<Vec<F>, SynthesisError> {
    // the usual H query has domain-1 powers. Z has domain powers. So HZ has 2*domain-1 powers.
    let mut scalars = (0..2 * max_power + 1)
        .into_par_iter()
        .map(|i| delta_inverse * t.pow([i as u64]))
        .collect::<Vec<_>>();
    let domain_size = scalars.len();
    let domain = D::new(domain_size).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
    // generate the lagrange coefficients
    domain.ifft_in_place(&mut scalars);
    Ok(scalars.into_par_iter().skip(1).step_by(2).collect())
}
