use p256::elliptic_curve::{Curve};

pub struct ESPublic<C>
where C : Curve
{
    inner: VerifyingKey<C>,
}