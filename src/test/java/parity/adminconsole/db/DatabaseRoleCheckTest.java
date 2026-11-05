package parity.adminconsole.db;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import parity.adminconsole.lifecycle.ConfigurationRefusedException;

/** Review F7: an app role that row-level security doesn't bind is refused at start (exit 2). */
class DatabaseRoleCheckTest {

    @Test
    void superuserBypassRlsAndOwnersAreRefusedThePlainAppRolePasses() {
        assertThatThrownBy(() -> DatabaseRoleCheck.refuse(new DatabaseRoleCheck.Role(true, false, false)))
                .isInstanceOf(ConfigurationRefusedException.class).hasMessageContaining("superuser");
        assertThatThrownBy(() -> DatabaseRoleCheck.refuse(new DatabaseRoleCheck.Role(false, true, false)))
                .isInstanceOf(ConfigurationRefusedException.class).hasMessageContaining("BYPASSRLS");
        assertThatThrownBy(() -> DatabaseRoleCheck.refuse(new DatabaseRoleCheck.Role(false, false, true)))
                .isInstanceOf(ConfigurationRefusedException.class).hasMessageContaining("owns");
        assertThatCode(() -> DatabaseRoleCheck.refuse(new DatabaseRoleCheck.Role(false, false, false))).doesNotThrowAnyException();
    }
}
