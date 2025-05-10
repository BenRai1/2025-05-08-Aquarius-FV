use soroban_sdk::Address;

use access_control::management::SingleAddressManagementTrait;
use access_control::access::AccessControlTrait;
use access_control::role::Role;

use crate::certora_specs::ACCESS_CONTROL;

    // function to get the address of any role
    pub fn get_role_address_any_safe(role: &Role) -> Option<Address> {
        let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL };
        return acc_ctrl.as_ref().unwrap().get_role_safe(role);
    }

    // //check if the address has auth
    // pub fn has_auth_save(address: Address) ->bool {
    //      if address.env.check_auth(address).is_ok() {
    //         true
    //     } else {
    //         false
    //     }
    // }

//----------OLD CODE START------------------
    pub fn get_role_address() -> Address {
        let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL };
        return acc_ctrl.as_ref().unwrap().get_role(&Role::Admin);
    }


    pub fn is_role(address: &Address, role: &Role) -> bool {
        let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL };
        return acc_ctrl.as_ref().unwrap().address_has_role(&address, role)
    }

//----------OLD CODE END------------------