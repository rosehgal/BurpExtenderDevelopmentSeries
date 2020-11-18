package burp;

public class BurpExtender implements IBurpExtender,
        IHttpListener, IProxyListener, IScannerListener, IExtensionStateListener {

    IBurpExtenderCallbacks callbacks;

    /* This we have already seen so far, this method we mostly use to register out Extender to Burp, by setting name
    getting helper, setting plugin level alerts etc.
     */
    @Override public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("Event Listener Plugin");
        callbacks.issueAlert("Plugin loaded");

        this.callbacks = callbacks;

        /*
        Since this class is implementing all the intertaces, this class must register itself as listener for all the
        implementations.
         */
        callbacks.registerHttpListener(this);
        callbacks.registerProxyListener(this);
        callbacks.registerScannerListener(this);
        callbacks.registerExtensionStateListener(this);

        /*
        Since we are implementing event listener for 4 different class, we are registering it for 4 times for various
         Listeners.
         Plugin registration is required to let Burp know what all events this plugin is looking for.
         */
    }

    /*
    This function belongs to IHTTPListener Interface.

    @toolFlag : take the Burp Suite plugin number, number to tool name can be obtained from callback.getToolName()
    @messageIsRequest : True if request, false id response
    @ messageInfo : Encapsulating details about an event.
     */
    @Override public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        callbacks.issueAlert(
                String.format("%s %s Called from %s",
                              messageIsRequest ? "HTTP Request : " : "HTTP Response : ",
                              messageInfo.getHttpService(),
                              callbacks.getToolName(toolFlag))
            );
    }

    /*
    This function implements IProxyListener
    @messageIsRequest : True if request, false id response
    @message : Encapsulating details about an event.
     */
    @Override public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        callbacks.issueAlert(
                String.format("%s %s Called from %s",
                              messageIsRequest ? "HTTP Request : " : "HTTP Response : ",
                              message.getMessageInfo(),
                              "Proxy")
        );
    }

    /*
    Implements IScannerListener
    @issue: encapsulates the details about the scan event.
     */
    @Override public void newScanIssue(IScanIssue issue) {
        callbacks.issueAlert("Scan triggered : " + issue.getIssueName());
    }

    /*
    This function implements IExtensionStateListener.
    */
    @Override public void extensionUnloaded() {
        callbacks.issueAlert("Extension Unloaded");
    }
}
