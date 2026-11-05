package parity.adminconsole.store;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import parity.adminconsole.contracts.Schemas;
import tools.jackson.databind.node.ObjectNode;

/** The writer's side of parity-store's contract (0.10.2): what goes to the admin topic, and that the console's commands validate. */
class StoreSchemaTest {

    private final Schemas schemas = new Schemas();

    @Test
    void theAdminTopicTakesExactlyTheWriteCommands() {
        assertThat(schemas.commands(Schemas.STORE_REQUESTS, "x-admin")).containsExactlyInAnyOrder("put_tenant", "delete_tenant",
                "set_placement", "delete_placement", "add_number", "remove_number", "add_sip_domain", "remove_sip_domain");
    }

    @Test
    void theConsolesCommandsValidateAndAPlantedFieldDoesNot() {
        ObjectNode put = StoreClient.command("put_tenant").put("tenant_id", "acme").put("name", "Acme Ltd").put("tier", "small")
                .put("expected_version", 0).put("schema_version", 1).put("id", "console-it:1").put("reply_to", "replies.admin-console");
        assertThat(schemas.check(Schemas.STORE_REQUESTS, put)).isEmpty();
        assertThat(schemas.check(Schemas.STORE_REQUESTS, put.deepCopy().put("caller_tenant", "acme"))).isNotEmpty();
        assertThat(schemas.check(Schemas.STORE_REQUESTS, put.deepCopy().put("reply_to", "admin.console.replies"))).isNotEmpty();
    }
}
