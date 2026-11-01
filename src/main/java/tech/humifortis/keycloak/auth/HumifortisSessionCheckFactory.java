package tech.humifortis.keycloak.auth;

import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/** Registers the session check; enable it in Authentication → Required actions. */
public class HumifortisSessionCheckFactory implements RequiredActionFactory {

    @Override public RequiredActionProvider create(KeycloakSession session) { return new HumifortisSessionCheck(); }
    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public void close() { }
    @Override public String getId() { return HumifortisSessionCheck.PROVIDER_ID; }
    @Override public String getDisplayText() { return "Humifortis session check"; }
}
