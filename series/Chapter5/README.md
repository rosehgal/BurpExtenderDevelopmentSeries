# Burp Suite Extender Plugin : Event Listeners

This chapter talks about how to register event listeners for various use cases. Event listener creation and registration we have already seen in the previous post [Listen for events from Proxy](series/Chapter3/README.md#listen-for-events-from-proxy).

This chapter is just the extension of those principle on similar ground. This chapter in detail talks about Event listener, and how they work in flow with Burp Callbacks. This chapter will also demonstrate how different event listeners can be configured in one single BurpExtender class.

Code will be registering Event Handlers from : `IHttpListener`, `IProxyListener`, `IScannerListener`, `IExtensionStateListener` Interfaces after implementing them.

- `IHttpListener`: 
  - The listener will be notified of requests and responses made
  by any Burp tool.
  - Extensions can perform custom analysis or modification of
  these messages by registering an HTTP listener.

- `IProxyListener`:
  - The listener will be notified of requests and responses being
  processed by the Proxy tool.
  - Extensions can perform custom analysis or modification of these messages, and control in-UI message interception, by
  registering a proxy listener.

- `IScannerListener`: 
  - The listener will be notified of new issues that are reported by the Scanner tool. - - Extensions can perform custom analysis or logging of Scanner issues by registering a Scanner listener.

- `IExtensionStateListener`: 
  - The listener will be notified of changes to the extension's state. <b>Note:</b> Any extensions that start background threads or open system resources (such as files or database connections) should register a listener and terminate threads / close resources when the extension is unloaded.

See this **Self Explained Example for Event listeners**:
```java
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

```

If everything goes well, output would look something like this :smile:

<p align=center>
<image src="../../static/images/chapter5/file.png" width=90%/>
</p>

#### [Code](../../code/BurpExtenderChapter5)

### [Next Chapter: Session token modification](series/Chapter6/README.md)

