package burp;

import javax.swing.*;
import java.awt.*;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

public class JWTDecodeTab implements IMessageEditorTab {
    private boolean editable;
    private ITextEditor txtArea;
    private byte[] currentMessage;

    private IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;

    public JWTDecodeTab(IMessageEditorController controller, boolean editable, IBurpExtenderCallbacks callbacks) {
        this.editable = editable;
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        /*
         Create an instance of Burp's text editor, to display our JWT decode data.
         */
        txtArea = this.callbacks.createTextEditor();
        txtArea.setEditable(editable);
    }

    /*
    This will set the name for this tab under Proxy.
     */
    @Override public String getTabCaption() {
        return "JWT Decode";
    }

    /*
    This will return the UI component to be display under Tab, Since we just want to display the text-editor
    (editable=false), we will return it. This has been created in Constructor.
     */
    @Override public Component getUiComponent() {
        return txtArea.getComponent();
    }

    /*
    This function will code the logic which will enable or disable this Tab. So since this is JWT decode tab plugin
    this should enable when there is JWT token present in there.

    To keep this simple I am assuming that, JWT token is present as the part of parameter name `jwtToken`.
    This logic can be complex and process for all the parameters and can check if there is any field with data JWT
    deserializable or not.

    We may see this use case later.
     */
    @Override public boolean isEnabled(byte[] content, boolean isRequest) {
        return isRequest && null != helpers.getRequestParameter(content, "jwtToken");
    }


    @Override public void setMessage(byte[] content, boolean isRequest) {
        /*
        If no data present in parameter
        */
        if (content == null) {
            /*
            clear our display, which is textArea
             */
            txtArea.setText(null);
            txtArea.setEditable(false);
        }
        else{
            /*
            Get the parameter value and decode it.
             */
            String jwtToken = helpers.getRequestParameter(content, "jwtToken").getValue();

            /*Since JWT token is <base64(alg)>.<base64(data)>.<base64(signature)> in simple terms, so we can use
            normal base64 decode functionality present in helpers to take this out data in plain text fmt.

            Steps :
                - split on '.', '.'(Period) is regex in Java which points to all chars so make sure you use patterns.
                    https://stackoverflow.com/a/3481842
                - decode the first two parts as third part is just signature.
             */
            List<String> jwtTokenParts = Arrays.asList(jwtToken.split(Pattern.quote(".")));
            String decodedJwtToken =
                    helpers.bytesToString(helpers.base64Decode(jwtTokenParts.get(0))) +"\r\n" +
                    helpers.bytesToString(helpers.base64Decode(jwtTokenParts.get(1)));

            callbacks.issueAlert("Decoded JWT token " + decodedJwtToken);
            /*
            Set this data in text field under tab.
             */
            txtArea.setText(helpers.stringToBytes(decodedJwtToken));
            txtArea.setEditable(editable);
        }
        currentMessage = content;
    }

    @Override public byte[] getMessage() {
        return currentMessage;
    }

    @Override public boolean isModified() {
        return txtArea.isTextModified();
    }

    @Override public byte[] getSelectedData() {
        return txtArea.getSelectedText();
    }
}
