package burp;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory{
    private IBurpExtenderCallbacks callbacks;

    @Override public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        callbacks.setExtensionName("Proxy Tab - JWT decoder");
        callbacks.issueAlert("Plugin loaded");

        callbacks.registerMessageEditorTabFactory(this);
    }

    @Override public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new JWTDecodeTab(controller, editable, callbacks);
    }
}

