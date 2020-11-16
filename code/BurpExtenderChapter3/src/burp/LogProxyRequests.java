package burp;

public class LogProxyRequests implements IHttpListener{

    private IBurpExtenderCallbacks iBurpExtenderCallbacks;
    private IExtensionHelpers iExtensionHelpers;

    public LogProxyRequests(IBurpExtenderCallbacks callbacks){
        /*
            For issuing alert to Alter tab.
         */
        iBurpExtenderCallbacks = callbacks;

        /*
            For parsing requests.
         */
        iExtensionHelpers = callbacks.getHelpers();
    }

    @Override public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        IRequestInfo requestInfo = null;

        /*
            Only listen for events from Burp Suite proxy && Only listen for requests.
         */
        if(toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && messageIsRequest == true)
            requestInfo = iExtensionHelpers.analyzeRequest(messageInfo);
            String domainName = requestInfo.getUrl().getHost();

            /*
                Log the domain name to Alerts tab.
             */
            iBurpExtenderCallbacks.issueAlert("Proxy: " + domainName);
    }
}
