use dep::aztec::context::PrivateContext;

use crate::entrypoint::{app::AppPayload, fee::FeePayload};
use crate::auth::{IS_VALID_SELECTOR, compute_authwit_message_hash};

struct AccountActions<Context> {
    context: Context,
    is_valid_impl: fn(&mut PrivateContext, Field) -> bool,
}

impl<Context> AccountActions<Context> {
    pub fn init(context: Context, is_valid_impl: fn(&mut PrivateContext, Field) -> bool) -> Self {
        AccountActions { context, is_valid_impl }
    }
}

/**
 * An implementation of the `AccountActions` struct specifically for the `PrivateContext`.
 * 
 * Implements logic to verify authorization and execute payloads in the given context.
 */
impl AccountActions<&mut PrivateContext> {

    /** 
     * Verifies the authorization for the `app_payload` and `fee_payload` hashes, then executes them.
     * 
     * Executes the `fee_payload` first to handle setup and then proceeds to execute `app_payload`.
     * 
     * @param app_payload The payload containing calls to be executed in the app phase.
     * @param fee_payload The payload containing calls to be executed in the setup phase.
     */
    // docs:start:entrypoint
    pub fn entrypoint(self, app_payload: AppPayload, fee_payload: FeePayload) {
        let valid_fn = self.is_valid_impl;

        let fee_hash = fee_payload.hash();
        assert!(valid_fn(self.context, fee_hash), "Fee payload is not authorized.");
        fee_payload.execute_calls(self.context);
        self.context.end_setup();

        let app_hash = app_payload.hash();
        assert!(valid_fn(self.context, app_hash), "App payload is not authorized.");
        app_payload.execute_calls(self.context);
    }
    // docs:end:entrypoint

    /**
     * Verifies that the `msg_sender` is authorized to use `inner_hash` with the account.
     * 
     * Computes the `message_hash` using the `msg_sender`, `chain_id`, `version`, and `inner_hash`.
     * Executes the `is_valid_impl` function to validate the message authorization.
     * 
     * Reverts if the message is not authorized.
     * 
     * @param inner_hash The hash of the message that the `msg_sender` is attempting to consume.
     * @return A field indicating the validation status.
     */
    // docs:start:verify_private_authwit
    pub fn verify_private_authwit(self, inner_hash: Field) -> Field {
        // Compute the message hash to ensure that only the intended sender can consume the message.
        let message_hash = compute_authwit_message_hash(
            self.context.msg_sender(),
            self.context.chain_id(),
            self.context.version(),
            inner_hash
        );
        let valid_fn = self.is_valid_impl;
        assert!(valid_fn(self.context, message_hash), "Message not authorized by account.");
        IS_VALID_SELECTOR
    }
    // docs:end:verify_private_authwit
}
