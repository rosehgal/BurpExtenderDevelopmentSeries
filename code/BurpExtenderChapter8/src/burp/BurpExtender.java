package burp;

public class BurpExtender implements IBurpExtender {
    @Override public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("JWT Decode Extension");

        callbacks.addSuiteTab(new JWTDecodeTab(callbacks));
    }
}
