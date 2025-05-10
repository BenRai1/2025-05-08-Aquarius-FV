use soroban_sdk::{Address, Env, Vec, BytesN};
// use soroban_sdk::Env;

use cvlr::asserts::{cvlr_assert, cvlr_assume};
use cvlr::{clog, cvlr_satisfy};
use cvlr_soroban::nondet_address;
use cvlr_soroban_derive::rule;

use crate::certora_specs::util::{get_role_address, is_role, get_role_address_any_safe};
pub use crate::contract::FeesCollector;
use access_control::role::Role;
use upgrade;

use crate::interface::AdminInterface;
use upgrade::interface::UpgradeableContract;
use upgrade::constants::UPGRADE_DELAY;

//------------------------------- RULES TEST START ----------------------------------

    

    // UPGRADE: if upgrate is cancled, it can no longer be applied 
    

  
    // apply_upgrade(): reverts if future_wasm == 0
  
    // apply_upgrade(): sets upgrade_deadline == 0
  
    // apply_upgrade(): sets current wasm to future_wasm

    
    
    
    
    
    
    
   




   
//------------------------------- RULES TEST END ----------------------------------

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

//------------------------------- RULES PROBLEMS START ----------------------------------

//------------------------------- RULES OK START ------------------------------------
    

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
        cvlr_assume!(!is_role(&admin, &Role::Admin));
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
        cvlr_assume!(!is_role(&admin, &Role::Admin));
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
        let is_set = get_role_address_any_safe(&Role::Admin).is_some();
        cvlr_assume!(is_set == true);

        let addr = get_role_address();
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
        let addr = get_role_address();
        // syntax of how to use `clog!`. This is helpful for calltrace when a rule fails.
        clog!(cvlr_soroban::Addr(&addr));
        cvlr_assert!(addr == address);
    }

    #[rule]
    pub fn only_emergency_admin_sets_emergency_mode(e: Env) {
        let address = nondet_address();
        let value: bool = cvlr::nondet();
        cvlr_assume!(!is_role(&address, &Role::EmergencyAdmin));
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