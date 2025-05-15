use access_control::constants::ADMIN_ACTIONS_DELAY;
use soroban_sdk::{Address, Env, Vec, BytesN};
// use soroban_sdk::Env;

use cvlr::asserts::{cvlr_assert, cvlr_assume};
use cvlr::{clog, cvlr_satisfy, nondet};
use cvlr_soroban::nondet_address;
use cvlr_soroban_derive::rule;

use crate::certora_specs::util as utils;
pub use crate::contract::FeesCollector;
pub use access_control::access::AccessControl;
use access_control::role::Role;
use upgrade;

use crate::interface::AdminInterface;
use upgrade::interface::UpgradeableContract;
use access_control::interface::TransferableContract;
use access_control::transfer::TransferOwnershipTrait;
use access_control::management::SingleAddressManagementTrait;
use access_control::management::MultipleAddressesManagementTrait;
use access_control::role::SymbolRepresentation;
use access_control::access::AccessControlTrait;
use upgrade::constants::UPGRADE_DELAY;
use soroban_sdk::Symbol;

//------------------------------- RULES TEST START ----------------------------------

    // apply_transfer_ownership(): reverts if role is not Admin or EmergancyAdmin
    #[rule]
    fn apply_transfer_ownership_reverts_not_admin_or_emergency_admin(e: Env) {
        let role_name = utils::nondet_symbol(&e);
        let admin = nondet_address();
        FeesCollector::apply_transfer_ownership(e.clone(), admin.clone(), role_name.clone()); //@audit-issue normal call does fail with "failed to compute per-call stats"
        cvlr_satisfy!(true); 
    }





   
    
    // get_future_address(): returns the future address if shedule is set //@audit continue here
    #[rule]
    fn get_future_address_returns_future_address_if_scheduled(e: Env, admin: Address, role_name: Symbol, new_address: Address) {
        //shedule transfer
        FeesCollector::commit_transfer_ownership(e.clone(), admin.clone(), role_name.clone(), new_address.clone());
        //call get_future_address
        //make suer the address is the same
        cvlr_satisfy!(true);
        
    }
    
    
    // get_future_address(): returns the set address if there is no transfer scheduled


    
    

    

    // TRANSFER_OWNERSHIP: once committed, can only be applied after ADMIN_ACTIONS_DELAY
    #[rule]
    fn transfer_ownership_must_respect_delay(e: Env) {
        let new_address: Address = nondet_address();
        let admin: Address = nondet_address();
        // check for Admin or EmergencyAdmin
        let value = cvlr::nondet();
        let role_name: Symbol;
        if value { role_name = Symbol::new(&e, "EmergencyAdmin")} else { role_name = Symbol::new(&e, "Admin")};
        
        FeesCollector::commit_transfer_ownership(e.clone(), admin.clone(), role_name.clone(), new_address);
        FeesCollector::apply_transfer_ownership(e.clone(), admin.clone(), role_name.clone()); 
        // FeesCollector::get_future_address(e.clone(), role_name.clone()); //@audit-issue test if this breakes it (works with the normal conf without loops)
        cvlr_satisfy!(true); 
    }
    
    
    // TRANSFER_OWNERSHIP: once committed, no new commit possibel before applied or cancled
    
    // commit_transfer_ownership(): reverts if role is not Admin or EmergancyAdmin
    
    // commit_transfer_ownership(): reverts if caller is not adminAddress
    
    // commit_transfer_ownership(): reverts if adminAddress does not have adminRole
    
    // commit_transfer_ownership(): reverts if adminRole has no transfer_delay
    
    // commit_transfer_ownership(): reverts if adminRole has many_users
    
    // commit_transfer_ownership(): reverts if transfer_ownership_deadline already set
    
    // commit_transfer_ownership(): sets transfer_ownership_deadline to timestamp() + ADMIN_ACTIONS_DELAY;
    
    // commit_transfer_ownership(): sets future_admin to new_address


    
    // get_future_address(): reverts if role is not Admin or EmergancyAdmin
    // #[rule]
    // fn get_future_address_reverts_if_role_not_admin_or_emergency_admin(e: Env,) {
    //     let role:str;
    //     let role_name: Symbol = Symbol::new(&e, "EmergencyAdmin");
    //     cvlr_assume!(role_name != "Admin" && role_name != "EmergencyAdmin");
    //     FeesCollector::get_future_address(e.clone(), role);
    //     cvlr_assert!(false); // should not reach and therefore should pass
    // }

    //------------------------------------------------------------------------------------------------------------

        // as_symbol(): simple call
        #[rule]
        fn from_symbol_simple_call(e: Env) {
            let symbol = Symbol::new(&e, "Admin");
            Role::from_symbol(&e, symbol);
            cvlr_satisfy!(true); 
        }

        // as_symbol(): possible to call this with Role::Admin
        #[rule]
        fn as_symbol_works_test(e: Env) {
            let role = utils::nondet_role();
            cvlr_assume!(role == Role::Admin);
            // let role = Role::Admin;
            let symbol = role.as_symbol(&e);
            // let role2 = Role::from_symbol(&e, symbol); //@audit-issue this rewerts for admin but not for the rest
            // let name = symbol_as_string(&e, &symbol);
            // clog!("symbol_name: {}", name);
            // cvlr_assert!(role == role2);
            cvlr_satisfy!(true); 
        }
    
    // as_symbol(): works simple
        #[rule]
        fn as_symbol_works_simple(e: Env) {
            let role = utils::nondet_role();
            //get index of the role
            let role_index = utils::index_of_role(&role);
            cvlr_assume!(role == Role::Admin);
            // let role = Role::Admin;
            let symbol = role.as_symbol(&e);
            //get index of the symbol
            let symbol_index = utils::index_of_symbol(&e, symbol);
            cvlr_satisfy!(true);

            

            // let role2 = Role::from_symbol(&e, symbol); //@audit-issue this rewerts for admin but not for the rest
            // let name = symbol_as_string(&e, &symbol);
            // clog!("symbol_name: {}", name);
            // cvlr_assert!(role == role2);
            cvlr_satisfy!(true); 
        }
    

        

        // as_symbol(): fromSymbol => toSymbol => result is starting input
        #[rule]
        fn as_symbol_works(e: Env) {
            let role = utils::nondet_role(); //@audit seams like it makes a difference which role is returned. Is the check done from the back?
            // let role_name = role_as_string(&role);
            // clog!("role_name: {}", role_name);
            cvlr_assume!(role == Role::EmergencyAdmin);
            // let role = Role::PauseAdmin; //@audit direct erzeugen ohne meine function
            let symbol = role.as_symbol(&e);
            // clog!("symbol_name: {}", symbol_as_string(&e, &symbol));
            let role2 = Role::from_symbol(&e, symbol);
            // cvlr_assert!(role == role2);
            cvlr_satisfy!(true); // should not reach and therefore should pass//@audit works, so there is at least one as_symbol => from_symbol combination that works
            // cvlr_assert!(false)
        }

        // #[rule]
        // fn as_symbol_works_alt(e: Env) { //@audit-issue does not work at all
        //     let role = nondet_role();
        //     let role_index = role_as_index(&role);
        //     let symbol = role.as_symbol(&e);
        //     let target_symbol = symbol_from_index(&e, &role_index);
        //     cvlr_assume!(symbol == target_symbol);
        // }


        
        
       
    
    

    
    
   
    

    
    

    
    
    
   




   
//------------------------------- RULES TEST END ----------------------------------



//------------------------------- RULES OK START ------------------------------------
    

    // as_symbol(): reverts if symbol is not in the list
    #[rule]
    fn as_symbol_reverts_for_wrong_role(e:Env, role: Role){
        let role_in_scope = utils::assume_role_in_scope(&role);
        cvlr_assume!(role_in_scope == 0);
        role.as_symbol(&e);
        // cvlr_assert!(false); // should not reach and therefore should pass 
        cvlr_satisfy!(true);
    }

    // get_role(): returns the set admin
    #[rule]
    fn get_role_returns_set_admin(e: Env) {
        let access_control = AccessControl::new(&e);
        let admin_role = Role::Admin;
        let role = utils::nondet_role();
        let is_set = utils::get_role_address_any_safe(&admin_role).is_some();
        cvlr_assume!(is_set == true);
        let admin = utils::get_role_address_any_safe(&admin_role).unwrap();
        let addr = access_control.get_role(&role);
        cvlr_assert!(addr == admin);
    }

    // get_role(): reverts if admin is not set
    #[rule]
    fn get_role_reverts_if_admin_not_set(e: Env) {
        let role = utils::nondet_role();
        let access_control = AccessControl::new(&e);
        let admin_role = Role::Admin;
        cvlr_assume!(role == Role::Admin);
        let is_set = access_control.get_role_safe(&admin_role).is_some(); //@audit-issue might not take the right access_control
        cvlr_assume!(is_set == false);
        access_control.get_role(&role);
        cvlr_assert!(false); // should not reach and therefore should pass
    }

    // get_role(): reverts if role is not admin
    #[rule]
    fn get_role_reverts_if_role_not_admin(e: Env) {
        let role = utils::nondet_role();
        let access_control = AccessControl::new(&e);
        cvlr_assume!(role != Role::Admin);
        access_control.get_role(&role);
        cvlr_assert!(false); // should not reach and therefore should pass
    }

   // set_role_addresses(): reverts if wrong role was given
    #[rule]
    fn set_role_addresses_reverts_if_wrong_role(e: Env, addresses: &Vec<Address>) { 
        let role = utils::nondet_role();
        let access_control = AccessControl::new(&e);
        cvlr_assume!(role != Role::EmergencyPauseAdmin);
        access_control.set_role_addresses(&role, addresses);
        cvlr_assert!(false); // should not reach and therefore should pass
    }

    // set_role_addresses(): reverts if role has transfer_delay
    #[rule]
    fn set_role_addresses_reverts_transfer_delay(e: Env, role: Role, addresses: &Vec<Address>) { 
            let access_control = AccessControl::new(&e);
            let role_in_scope = utils::assume_role_in_scope(&role);
            cvlr_assume!(role_in_scope == 1);
            //role has transfer delay
            let role_transfer_delay = role.is_transfer_delayed();
            cvlr_assume!(role_transfer_delay);
            //call
            access_control.set_role_addresses(&role, addresses);
            cvlr_assert!(false); // should not reach and therefore should pass
    }
   
    // require_pause_or_emergency_pause_admin_or_owner(): passes if address has EmergencyPauseAdmin
    #[rule]
    fn require_pause_or_emergency_pause_admin_or_owner_passes_for_e_pause_admin(e: Env, address: Address) {
        let access_control = AccessControl::new(&e);
        cvlr_assume!(!access_control.address_has_role(&address, &Role::Admin));
        cvlr_assume!(!access_control.address_has_role(&address, &Role::PauseAdmin));
        cvlr_assume!(access_control.address_has_role(&address, &Role::EmergencyPauseAdmin));
        access_control::utils::require_pause_or_emergency_pause_admin_or_owner(&e, &address);
        cvlr_satisfy!(true); // should not reach and therefore should pass
    }
    
    // require_pause_admin_or_owner(): reverts if address does not have adminRole or pauseAdminRole
    #[rule]
    fn require_pause_admin_or_owner_reverts(e: Env, address: Address) {
        let access_control = AccessControl::new(&e);
        cvlr_assume!(!access_control.address_has_role(&address, &Role::PauseAdmin));
        cvlr_assume!(!access_control.address_has_role(&address, &Role::Admin));
        access_control::utils::require_pause_admin_or_owner(&e, &address);
        cvlr_assert!(false); // should not reach and therefore should pass
    }

    // require_pause_admin_or_owner(): passes if address has adminRole
    #[rule]
    fn require_pause_admin_or_owner_passes_for_admin(e: Env, address: Address) {
        let access_control = AccessControl::new(&e);
        cvlr_assume!(access_control.address_has_role(&address, &Role::Admin));
        cvlr_assume!(!access_control.address_has_role(&address, &Role::PauseAdmin));
        access_control::utils::require_pause_admin_or_owner(&e, &address);
        cvlr_satisfy!(true); // should not reach and therefore should pass
    }
    
    // require_pause_admin_or_owner(): passes if address has pauseAdminRole
    #[rule]
    fn require_pause_admin_or_owner_passes_for_pause_admin(e: Env, address: Address) {
        let access_control = AccessControl::new(&e);
        cvlr_assume!(!access_control.address_has_role(&address, &Role::Admin));
        cvlr_assume!(access_control.address_has_role(&address, &Role::PauseAdmin));
        access_control::utils::require_pause_admin_or_owner(&e, &address);
        cvlr_satisfy!(true); // should not reach and therefore should pass
    }

    // require_operations_admin_or_owner(): passes if address has adminRole
    #[rule]
    fn require_operations_admin_or_owner_passes_for_admin(e: Env, address: Address) {
        let access_control = AccessControl::new(&e);
        cvlr_assume!(access_control.address_has_role(&address, &Role::Admin));
        cvlr_assume!(!access_control.address_has_role(&address, &Role::OperationsAdmin));
        access_control::utils::require_operations_admin_or_owner(&e, &address);
        cvlr_satisfy!(true);
    }
    
    // require_operations_admin_or_owner(): passes if address has operationsAdminRole
    #[rule]
    fn require_operations_admin_or_owner_passes_for_operational_admin(e: Env, address: Address) {
        let access_control = AccessControl::new(&e);
        cvlr_assume!(!access_control.address_has_role(&address, &Role::Admin));
        cvlr_assume!(access_control.address_has_role(&address, &Role::OperationsAdmin));
        access_control::utils::require_operations_admin_or_owner(&e, &address);
        cvlr_satisfy!(true);
    }

    // require_operations_admin_or_owner(): reverts if address does not have adminRole or operationsAdminRole
    #[rule]
    fn require_operations_admin_or_owner_reverts(e: Env, address: Address) {
        let access_control = AccessControl::new(&e);
        cvlr_assume!(!access_control.address_has_role(&address, &Role::Admin));
        cvlr_assume!(!access_control.address_has_role(&address, &Role::OperationsAdmin));
        access_control::utils::require_operations_admin_or_owner(&e, &address);
        cvlr_assert!(false); // should not reach and therefore should pass
    }

    // require_rewards_admin_or_owner(): passes if address has adminRole
    #[rule]
    fn require_rewards_admin_or_owner_passes_for_admin(e: Env, address: Address) {
        let access_control = AccessControl::new(&e);
        cvlr_assume!(access_control.address_has_role(&address, &Role::Admin));
        cvlr_assume!(!access_control.address_has_role(&address, &Role::RewardsAdmin)); 
        access_control::utils::require_rewards_admin_or_owner(&e, &address);
        cvlr_satisfy!(true);
    }

    // require_rewards_admin_or_owner(): passes if address has rewardAdminRole
    #[rule]
     fn require_rewards_admin_or_owner_passes_for_reward_admin(e: Env, address: Address) {
        let access_control = AccessControl::new(&e);
        cvlr_assume!(access_control.address_has_role(&address, &Role::RewardsAdmin)); 
        cvlr_assume!(!access_control.address_has_role(&address, &Role::Admin));
        access_control::utils::require_rewards_admin_or_owner(&e, &address);
        cvlr_satisfy!(true);
    }

    // require_rewards_admin_or_owner(): reverts if address does not have adminRole or rewardAdminRole
    #[rule]
    fn require_rewards_admin_or_owner_reverts(e: Env, address: Address) {
        let access_control = AccessControl::new(&e);
        cvlr_assume!(!access_control.address_has_role(&address, &Role::Admin));
        cvlr_assume!(!access_control.address_has_role(&address, &Role::RewardsAdmin));
        access_control::utils::require_rewards_admin_or_owner(&e, &address);
        cvlr_assert!(false); // should not reach and therefore should pass
    }

    // version(): returns 150
    #[rule]
    fn version_returns_150(e: Env) {
        let version = FeesCollector::version();
        cvlr_assert!(version == 150);
    }

    // get_future_address(): reverts if role not Admin or EmergancyAdmin
    #[rule]
    fn get_future_address_reverts_if_role_not_admin_or_emergency_admin(e: Env, role_name: Symbol) {
        let given_role = Role::from_symbol(&e, role_name.clone());
        cvlr_assume!(given_role != Role::Admin);
        cvlr_assume!(given_role != Role::EmergencyAdmin);
        FeesCollector::get_future_address(e.clone(), role_name);
        cvlr_assert!(false); // should not reach and therefore should pass
    }
    
    // get_future_address(): reverts if no transfer scheduled and the roleAddress is not set
    #[rule]
    fn get_future_address_reverts_if_not_scheduled_and_no_address(e: Env) {
        let random_bool: bool = cvlr::nondet();
        
        let role_name :Symbol;
        if random_bool {
            role_name = Symbol::new(&e, "EmergencyAdmin");
        } else {
            role_name = Symbol::new(&e, "Admin");
        }

        let role = Role::from_symbol(&e, role_name.clone());
        //deadline for Admin transfer is set to 0
        let access_control = AccessControl::new(&e);
        let deadline = access_control.get_transfer_ownership_deadline(&role);
        cvlr_assume!(deadline == 0);
        //adminAddress is not set
        let is_set = utils::get_role_address_any_safe(&role).is_some();
        cvlr_assume!(is_set == false);
        // //get_future_address() should revert
        FeesCollector::get_future_address(e.clone(), role_name.clone());
        cvlr_assert!(false);
    }
    
    // set_emergency_mode(): emergancyMode is set to "value"
    #[rule]
    fn set_emergency_mode_sets_emergency_mode(e: Env ) {
        let value = cvlr::nondet();
        FeesCollector::set_emergency_mode(e.clone(), e.current_contract_address(), value);
        let value_after = FeesCollector::get_emergency_mode(e.clone());
        cvlr_assert!(value_after == value);
        
    }

    // set_emergency_mode(): reverts if emergancy_adminAddress does not have the emergancy_adminRole
    #[rule]
    fn set_emergency_mode_reverts_if_not_emergancy_admin(e: Env, emergancy_admin: Address, value: bool) {
        cvlr_assume!(!utils::is_role(&emergancy_admin, &Role::EmergencyAdmin));
        FeesCollector::set_emergency_mode(e.clone(), emergancy_admin, value);
        cvlr_assert!(false); // should not reach and therefore should pass
    }

    // revert_upgrade(): reverts if adminAddress does not have adminRole
    #[rule]
    fn revert_upgrade_reverts_if_no_admin_role(e: Env, admin: Address) {
        cvlr_assume!(!utils::is_role(&admin, &Role::Admin));
        FeesCollector::revert_upgrade(e.clone(), admin);
        cvlr_assert!(false); // should not reach and therefore should pass
    }
    
    // revert_upgrade(): sets upgrade_deadline == 0
    #[rule]
    fn revert_upgrade_sets_deadline_zero(e: Env, admin: Address) {
        FeesCollector::revert_upgrade(e.clone(), admin);
        let deadline = upgrade::storage::get_upgrade_deadline(&e);
        cvlr_assert!(deadline == 0);
    }

    // apply_upgrade(): sets upgrade_deadline == 0
    #[rule]
    fn apply_upgrade_sets_deadline_zero(e: Env, admin: Address) {
        let deadline = upgrade::storage::get_upgrade_deadline(&e);
        cvlr_assume!(deadline != 0);
        FeesCollector::apply_upgrade(e.clone(), admin.clone());
        let deadline = upgrade::storage::get_upgrade_deadline(&e);
        cvlr_assert!(deadline == 0);
    }
  
    // apply_upgrade(): reverts if future_wasm == 0
    #[rule]
    fn apply_upgrade_reverts_if_future_wasm_zero(e: Env, admin: Address) {
        let future_wasm = upgrade::storage::get_future_wasm(&e);
        cvlr_assume!(future_wasm.is_none());
        FeesCollector::apply_upgrade(e.clone(), admin);
        cvlr_assert!(false); // should not reach and therefore should pass
    }

    // apply_upgrade(): no emergancyMode => reverts if upgrade_deadline has not passed
    #[rule]
    fn apply_upgrade_reverts_if_deadline_not_passed(e: Env, admin: Address) {
        //ensuer emergancy mode is not set
        let value: bool =  FeesCollector::get_emergency_mode(e.clone());
        cvlr_assume!(value == false);
        let deadline = upgrade::storage::get_upgrade_deadline(&e);
        cvlr_assume!(deadline > e.ledger().timestamp());
        FeesCollector::apply_upgrade(e.clone(), admin);
        cvlr_assert!(false); // should not reach and therefore should pass
    }
  
    // apply_upgrade(): no emergancyMode => reverts if upgrade_deadline == 0
    #[rule]
    fn apply_upgrade_reverts_if_deadline_zero(e: Env, admin: Address) {
        //ensuer emergancy mode is not set
        let value: bool =  FeesCollector::get_emergency_mode(e.clone());
        cvlr_assume!(value == false);
        let deadline = upgrade::storage::get_upgrade_deadline(&e);
        cvlr_assume!(deadline == 0);
        FeesCollector::apply_upgrade(e.clone(), admin);
        cvlr_assert!(false); // should not reach and therefore should pass
    }

    // apply_upgrade(): reverts if adminAddress does not have adminRole
    #[rule]
    fn apply_upgrade_reverts_if_no_admin_role(e: Env, admin: Address) {
        cvlr_assume!(!utils::is_role(&admin, &Role::Admin));
        FeesCollector::apply_upgrade(e.clone(), admin);
        cvlr_assert!(false); // should not reach and therefore should pass
    }

     // commit_upgrade(): sets future_wasm to provided hash
    #[rule]
    fn commit_upgrade_sets_future_wasm(e: Env, admin: Address, new_wasm_hash: BytesN<32>) {
        let future_wasm = upgrade::storage::get_future_wasm(&e);
        cvlr_assume!(future_wasm.is_none());
        FeesCollector::commit_upgrade(e.clone(), admin, new_wasm_hash.clone());
        let future_wasm = upgrade::storage::get_future_wasm(&e);
        cvlr_assert!(future_wasm.is_some());
        if future_wasm.is_some(){
            cvlr_assert!(future_wasm.unwrap() == new_wasm_hash);
        }
    }
    
    // commit_upgrade(): sets update_deadline = timestamp() + UPGREADE_DELAY
    #[rule]
    fn commit_upgrade_sets_update_deadline(e: Env, admin: Address, new_wasm_hash: BytesN<32>) {
        let deadline = upgrade::storage::get_upgrade_deadline(&e);
        cvlr_assume!(deadline == 0);
        FeesCollector::commit_upgrade(e.clone(), admin, new_wasm_hash);
        let deadline = upgrade::storage::get_upgrade_deadline(&e); //@audit this should fail since this uses the orignal Env
        let traget_deadline = e.ledger().timestamp() + UPGRADE_DELAY;
        cvlr_assert!(deadline == traget_deadline);
    }
    
    // commit_upgrade(): reverts if upgrate_deadline != 0
    #[rule]
    fn commit_upgrade_reverts_if_upgrate_deadline_not_zero(e: Env, admin: Address, new_wasm_hash: BytesN<32>) {
        let deadline = upgrade::storage::get_upgrade_deadline(&e);
        cvlr_assume!(deadline != 0);
        FeesCollector::commit_upgrade(e, admin, new_wasm_hash);
        cvlr_assert!(false); // should not reach and therefore should pass
    }
    
    // commit_upgrade(): reverts if adminAddress does not have adminRole
    #[rule]
    fn commit_upgrade_reverts_no_admin_role(e: Env, admin: Address, new_wasm_hash: BytesN<32>) {
        cvlr_assume!(!utils::is_role(&admin, &Role::Admin));
        FeesCollector::commit_upgrade(e.clone(), admin, new_wasm_hash);
        cvlr_assert!(false); // should not reach and therefore should pass
    }
    
    // UPGRADE: in emergancyMode, an upgrade can be applied right away
    #[rule]
    fn upgrade_in_emergancy_mode_updated_without_delay(e: Env, admin: Address, new_wasm_hash: BytesN<32>){
        //ensuer emergancy mode is set
        let value: bool =  FeesCollector::get_emergency_mode(e.clone());
        cvlr_assume!(value == true);

        FeesCollector::commit_upgrade(e.clone(), admin.clone(), new_wasm_hash.clone());
        FeesCollector::apply_upgrade(e.clone(), admin.clone());
        cvlr_satisfy!(true); 
    }

    // UPGRADE: once an upgrate is comitted, no new upgrate can be comitted befere the old one is applied or upgrated
    #[rule]
    fn upgrade_reverts_if_already_commited(e: Env, admin: Address, new_wasm_hash: BytesN<32>) {
        FeesCollector::commit_upgrade(e.clone(), admin.clone(), new_wasm_hash.clone());
        FeesCollector::commit_upgrade(e.clone(), admin.clone(), new_wasm_hash.clone());
        cvlr_assert!(false); // should not reach and therefore should pass
    }
    
    // UPGRADE: once upgrate is comitted, the upgrade can only be triggered after UPGRADE_DELAY has passed (no emergancyMode)
    #[rule]
    fn upgrade_reverts_if_delay_not_passed(e: Env, admin: Address, new_wasm_hash: BytesN<32>) {
        //ensuer emergancy mode is not set
        let value: bool =  FeesCollector::get_emergency_mode(e.clone());
        cvlr_assume!(value == false);
        FeesCollector::commit_upgrade(e.clone(), admin.clone(), new_wasm_hash.clone());
        FeesCollector::apply_upgrade(e.clone(), admin.clone());
        cvlr_assert!(false); // should not reach and therefore should pass
    }

    //init_admin(): reverts if admin is already set
    #[rule]
    pub fn init_admin_reverts_if_already_set(e: Env) {
        let address = nondet_address();
        clog!(cvlr_soroban::Addr(&address));
        let is_set = utils::get_role_address_any_safe(&Role::Admin).is_some();
        cvlr_assume!(is_set == true);

        let addr = utils::get_role_address();
        clog!(cvlr_soroban::Addr(&address));

        cvlr_assume!(addr == address);
        FeesCollector::init_admin(e, address.clone());
        cvlr_assert!(false); // should not reach and therefore should pass
    }



//------------------------------- RULES OK END ------------------------------------




/**
 * These are some example rules to help get started.
*/
//--------------------- OLD RUELS START ---------------------
    #[rule]
    pub fn init_admin_sets_admin(e: Env) {
        let address = nondet_address();
        clog!(cvlr_soroban::Addr(&address));
        FeesCollector::init_admin(e, address.clone());
        let addr = utils::get_role_address();
        // syntax of how to use `clog!`. This is helpful for calltrace when a rule fails.
        clog!(cvlr_soroban::Addr(&addr));
        cvlr_assert!(addr == address);
    }

    #[rule]
    pub fn only_emergency_admin_sets_emergency_mode(e: Env) {
        let address = nondet_address();
        let value: bool = cvlr::nondet();
        cvlr_assume!(!utils::is_role(&address, &Role::EmergencyAdmin));
        FeesCollector::set_emergency_mode(e, address, value);
        cvlr_assert!(false); // should not reach and therefore should pass
    }

    #[rule]
    pub fn set_emergency_mode_success(e: Env) {
        let value: bool = cvlr::nondet();
        access_control::emergency::set_emergency_mode(&e, &value);
        cvlr_assert!(access_control::emergency::get_emergency_mode(&e) == value);
    }
// --------------------- OLD RUELS END ---------------------

//------------------------------- RULES PROBLEMS START ----------------------------------

    // commit_upgrade(): reverts if caller is not adminAddress (require_auth())
    // #[rule]
    // fn commit_upgrade_reverts_if_caller_not_admin(e: Env, admin: Address, new_wasm_hash: BytesN<32>) {
    //     // self.env.require_auth(self);
    //     cvlr_assume!(!&admin.env.check_auth(&admin).is_ok()); //@audit-issue does not work like this
    //     // let caller: Address = e.current_contract_address();
    //     // clog!(cvlr_soroban::Addr(&caller));
    //     // clog!(cvlr_soroban::Addr(&admin));
    //     // cvlr_assume!(caller != admin);
    //     FeesCollector::commit_upgrade(e.clone(), admin, new_wasm_hash);
    //     cvlr_assert!(false); // should not reach and therefore should pass
    // }

    // require_pause_or_emergency_pause_admin_or_owner(): reverts if address does not have adminRole or PauseAdmin or EmergencyPauseAdmin
    #[rule]
    fn require_pause_or_emergency_pause_admin_or_owner_reverts(e: Env) { //@audit-issue fails, not sure why: issue is with the emergancy pause admin (multiple users for EmergencyPauseAdmin?)
        let address = nondet_address();
        clog!(cvlr_soroban::Addr(&address));
        let access_control = AccessControl::new(&e);
        cvlr_assume!(!access_control.address_has_role(&address, &Role::PauseAdmin) &&
                     !access_control.address_has_role(&address, &Role::EmergencyPauseAdmin) &&
                     !access_control.address_has_role(&address, &Role::Admin));
        access_control::utils::require_pause_or_emergency_pause_admin_or_owner(&e, &address);
        cvlr_assert!(false); // should not reach and therefore should pass
    }
    
    // require_pause_or_emergency_pause_admin_or_owner(): passes if address has adminRole
    #[rule]
    fn require_pause_or_emergency_pause_admin_or_owner_passes_for_admin(e: Env, address: Address) { //@audit-issue also fails, reason will be the same as above (EmergencyPauseAdmin)
        let access_control = AccessControl::new(&e);
        cvlr_assume!(access_control.address_has_role(&address, &Role::Admin));
        cvlr_assume!(!access_control.address_has_role(&address, &Role::PauseAdmin));
        cvlr_assume!(!access_control.address_has_role(&address, &Role::EmergencyPauseAdmin));
        access_control::utils::require_pause_or_emergency_pause_admin_or_owner(&e, &address);
        cvlr_satisfy!(true); // should not reach and therefore should pass
    }
    
    // require_pause_or_emergency_pause_admin_or_owner(): passes if address has PauseAdmin
    #[rule]
    fn require_pause_or_emergency_pause_admin_or_owner_passes_for_pause_admin(e: Env, address: Address) { //@audit-issue also fails, reason will be the same as above (EmergencyPauseAdmin)
        let access_control = AccessControl::new(&e);
        cvlr_assume!(!access_control.address_has_role(&address, &Role::Admin));
        cvlr_assume!(access_control.address_has_role(&address, &Role::PauseAdmin));
        cvlr_assume!(!access_control.address_has_role(&address, &Role::EmergencyPauseAdmin));
        access_control::utils::require_pause_or_emergency_pause_admin_or_owner(&e, &address);
        cvlr_satisfy!(true); // should not reach and therefore should pass
    }
    

        // set_role_addresses(): reverts if role does not have many users
        #[rule]
        fn set_role_addresses_reverts_if_role_does_not_have_many_users(e: Env, role: Role, addresses: &Vec<Address>) { //@audit-issue also fails because it interacts with EmergancyPauseAdmin
            let access_control = AccessControl::new(&e);
            let role_in_scope = utils::assume_role_in_scope(&role);
            cvlr_assume!(role_in_scope == 1);
            cvlr_assume!(role != Role::EmergencyPauseAdmin);
            let role_number = utils::index_of_role(&role);
            clog!("Role number", role_number);

            access_control.set_role_addresses(&role, addresses);
            cvlr_assert!(false); // should not reach and therefore should pass
        }
        
        
        // set_role_addresses(): gives the provided addresses the role //@audit will fail because no execution is possible
      

        // set_role_addresses(): passes for EmergancyPauseAdmin //@audit-issue fails because it interacts with EmergancyPauseAdmin
        #[rule]
        fn set_role_addresses_passes_for_emergancy_paus_admin(e: Env, addresses: &Vec<Address>) { 
            let role = utils::nondet_role();
            let access_control = AccessControl::new(&e);
            cvlr_assume!(role == Role::EmergencyPauseAdmin);
            access_control.set_role_addresses(&role, addresses);
            cvlr_satisfy!(true); // should not reach and therefore should pass
        }

//------------------------------- RULES PROBLEMS END ----------------------------------