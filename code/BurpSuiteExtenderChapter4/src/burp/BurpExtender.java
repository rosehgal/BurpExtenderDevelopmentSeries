package burp;

public class BurpExtender implements IBurpExtender {
    @Override public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("Intruder Processing");
        callbacks.issueAlert("Plugin loaded");

        callbacks.registerIntruderPayloadProcessor(new IntruderPayloadProcessor(callbacks));
    }
}
