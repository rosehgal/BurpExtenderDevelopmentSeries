package burp;

import java.util.List;

public class BurpExtender implements IBurpExtender, ISessionHandlingAction {
    IBurpExtenderCallbacks callbacks;
    IExtensionHelpers helpers;

    private static String SESSION_ID_KEY = "X-Custom-Session-Id";
    private static final byte[] SESSION_ID_KEY_BYTES = SESSION_ID_KEY.getBytes();
    private static final byte[] NEWLINE_BYTES = new byte[] { '\r', '\n' };

    @Override public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("Custom Session Token");
        callbacks.issueAlert("Plugin Loaded");
        callbacks.issueAlert(String.format("Session ID being used : %s", SESSION_ID_KEY));


        /*
        Register the SessionHandler
         */
        callbacks.registerSessionHandlingAction(this);
    }

    @Override public String getActionName() {
        return "Read user session token from Macro";
    }

    /*
    This function is executed after macro call and before a subsequent Scanner or Intruder call.
     */
    @Override public void performAction(IHttpRequestResponse currentRequest, IHttpRequestResponse[] macroItems) {
        /*
        Don't execute anything if there is no macro.
         */
        if(macroItems.length == 0) return;

        /*
        Extract Macro response
         */
        final byte[] macroResponse = macroItems[macroItems.length - 1].getResponse();

        /*
        Extract all headers from response
         */
        final List<String> headers = helpers.analyzeResponse(macroResponse).getHeaders();

        /*
        Extract the Custom Session token header from all headers
         */
        String sessionToken = null;
        for(String header : headers){
            if(!header.startsWith(SESSION_ID_KEY)) continue;
            callbacks.issueAlert("Scanning..");
            sessionToken = header.substring(SESSION_ID_KEY.length()).trim();
            callbacks.issueAlert(sessionToken);
        }

        /*
        If session token is not identified skip.
         */
        if(sessionToken == null) return;

        /*
        Otherwise, append the session token to currentRequest
         */
        final String req = helpers.bytesToString(currentRequest.getRequest());
        final int sessionTokenKeyStart = helpers.indexOf(helpers.stringToBytes(req),
                                                         SESSION_ID_KEY_BYTES,
                                                         false,
                                                         0,
                                                         req.length());
        final int sessionTokenKeyEnd = helpers.indexOf(helpers.stringToBytes(req),
                                                       NEWLINE_BYTES,
                                                       false,
                                                       sessionTokenKeyStart,
                                                       req.length());

        /*
        Join together First line + Session header line + rest of request
         */
        String newRequest = req.substring(0, sessionTokenKeyStart) +
                String.format("%s: %s", SESSION_ID_KEY, sessionToken) +
                req.substring(sessionTokenKeyStart + 1, sessionTokenKeyEnd);

        /*
        Update the current request headers
         */
        callbacks.issueAlert(newRequest);
        currentRequest.setRequest(helpers.stringToBytes(newRequest));
    }
}
