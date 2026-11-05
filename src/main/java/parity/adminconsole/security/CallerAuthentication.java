package parity.adminconsole.security;

import java.util.Collection;
import java.util.EnumSet;
import java.util.Set;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

/** An authenticated {@link Caller}; its authorities are {@code ROLE_<role>} for the tenant roles it holds. */
public final class CallerAuthentication extends AbstractAuthenticationToken {

    private static final long serialVersionUID = 1L;

    private final transient Caller caller;
    private final transient Jwt jwt;

    CallerAuthentication(Caller caller, Jwt jwt, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.caller = caller;
        this.jwt = jwt;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return jwt;
    }

    @Override
    public Caller getPrincipal() {
        return caller;
    }

    @Override
    public String getName() {
        return caller.subject();
    }

    /** Builds the caller from a token that passed {@link TokenChecks}. */
    public static final class FromJwt implements Converter<Jwt, AbstractAuthenticationToken> {
        @Override
        public AbstractAuthenticationToken convert(Jwt jwt) {
            Set<Role> roles = EnumSet.noneOf(Role.class);
            for (String r : TokenChecks.realmRoles(jwt)) {
                Role.fromClaim(r).ifPresent(roles::add);
            }
            Caller caller = new Caller(jwt.getSubject(), jwt.getClaimAsString("preferred_username"), roles,
                    jwt.getClaimAsString("tenant_id"));
            return new CallerAuthentication(caller, jwt,
                    roles.stream().map(r -> new SimpleGrantedAuthority("ROLE_" + r.claim())).toList());
        }
    }
}
