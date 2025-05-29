use crate::{access::AccessControl, storage::DataKey};
use crate::errors::AccessControlError;
use crate::role::Role;
use crate::storage::StorageTrait;
use soroban_sdk::{panic_with_error, Address, Vec};
use utils::bump::bump_instance;
// use cvlr::{clog, cvlr_satisfy, nondet};//@audit added for certora

pub trait SingleAddressManagementTrait {
    fn get_role_safe(&self, role: &Role) -> Option<Address>;
    fn get_role(&self, role: &Role) -> Address;
    fn set_role_address(&self, role: &Role, address: &Address);
}

pub trait MultipleAddressesManagementTrait {
    fn get_role_addresses(&self, role: &Role) -> Vec<Address>;
    fn set_role_addresses(&self, role: &Role, addresses: &Vec<Address>);
}

impl SingleAddressManagementTrait for AccessControl {
    fn get_role_safe(&self, role: &Role) -> Option<Address> {
        if role.has_many_users() {
            panic_with_error!(&self.0, AccessControlError::BadRoleUsage); //@audit-issue write rule to catch this
        }

        let key = self.get_key(role);
        bump_instance(&self.0);
        self.0.storage().instance().get(&key)
    }

    fn get_role(&self, role: &Role) -> Address {
        match role {
            Role::Admin => {}
            _ => {
                // only admin is guaranteed, use `get_role_safe` for other roles
                panic_with_error!(&self.0, AccessControlError::BadRoleUsage);
            }
        }
        

        match self.get_role_safe(role) { //i: this is never reached for other roles than admin becasue it reverts before
            Some(address) => address,
            None => panic_with_error!(&self.0, AccessControlError::RoleNotFound),
        
        }
    }

    fn set_role_address(&self, role: &Role, address: &Address) {
        if role.has_many_users() {
            panic_with_error!(&self.0, AccessControlError::BadRoleUsage);
        }

        // require delay if address is being replaced.
        // don't require delay if role is being set for the first time
        let addr = self.get_role_safe(role);
        if addr.is_some() && role.is_transfer_delayed() { //@audit-issue can not be used to change roles if they are set and have delay. Check where this is used and if this can be an issue.
            panic_with_error!(&self.0, AccessControlError::BadRoleUsage);
        }

        let key = DataKey::Admin;
        bump_instance(&self.0);
        self.0.storage().instance().set(&key, address); //@audit-issue !ISSUE! event emission missing (set_privileged_addrss)
    }

}

impl MultipleAddressesManagementTrait for AccessControl {
    fn get_role_addresses(&self, role: &Role) -> Vec<Address> {
        if !role.has_many_users() {
            panic_with_error!(&self.0, AccessControlError::BadRoleUsage);
        }

        let key = self.get_key(role);
        bump_instance(&self.0); 
        self.0
            .storage()
            .instance()
            .get(&key)
            .unwrap_or(Vec::new(&self.0))
    }

    // no delay-related code as we require it only for single addresses roles
    fn set_role_addresses(&self, role: &Role, addresses: &Vec<Address>) {
        if !role.has_many_users() || role.is_transfer_delayed() { //@audit-issue I dont have a rule which would chatch changes here because there is only one role (checkncloaser)
            panic_with_error!(&self.0, AccessControlError::BadRoleUsage);
        }

        let key = self.get_key(role);
        bump_instance(&self.0);
        self.0.storage().instance().set(&key, addresses);
    }
    
}
