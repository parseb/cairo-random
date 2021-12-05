%lang starknet
%builtins pedersen range_check ecdsa

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.math import assert_not_zero
from starkware.cairo.common.math_cmp import is_le
from starkware.cairo.common.signature import verify_ecdsa_signature


@storage_var
func poll_owner_public_key(poll_id : felt) -> (public_key : felt):
end

@storage_var
func registered_voters(poll_id : felt, voter_public_key : felt) -> (is_registered : felt):
end

@storage_var
func voting_state(pool_id : felt, answer : felt) -> (n_votes : felt):
end

@storage_var
func voter_state(pool_id : felt, voter_public_key : felt) -> (has_volter : felt):
end

@external
func init_pol{syscall_ptr : felt*, range_check_ptr, pedersen_ptr : HashBuiltin*}(
    pool_id : felt, public_key : felt)
):
let (is_poll_id_taken) = poll_owner_public_key.read(poll_deposit_id)

assert is_pool_id_taken = 0


poll_owner_public_key.write(poll_id = poll_id, value = public_key)

    return ()

end


@external 
func register_voter{
        syscall_ptr : felt*, range_check_ptr, pedersen_ptr : HashBuiltin*,
        ecdsa_ptr : SignatureBuiltin*}
        (pool_id : felt, voter_public_key : felt, r: felt s : felt): 
    
    let (owner_public_key) = poll_owner_public_key.read(poll_id=poll_id)

    assert_not_zero(owner_public_key)

    let (message) = hash2{hash_ptr=pedersen_ptr}(x=pool_id, y=voter_public_key)

    verify_ecdsa_signature(
        message=message , public_key=owner_public_key, signature_r = r, signature_s = s)

    registered_voters.write(poll_id=poll_id, voter_public_key=voter_public_key, value=1)

    return ()
end


@view
func get_voting_state{syscall_ptr : felt*, range_check_ptr, pedersen_ptr, HashBuiltin*}(
    poll_id : felt) -> (n_no_votes : felt, n_yest_votes : felt):

    let(n_no_votes) = voting_state.read(pool_id = pool_id, answer = 0)
    let(n_yes_votes) = voting_state.read(pool_id = pool_id, answer = 1)

    return (n_no_votes=n_no_votes, n_yes_votes=n_yes_votes)

end
