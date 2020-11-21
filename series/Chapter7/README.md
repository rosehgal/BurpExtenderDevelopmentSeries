# Burp Suite Extension - Create HTTP Proxy plugin Example - JWT token on the Go

If you have made this far, this would have definitely enticed you about Burp Suite Extender development a bit. And too take this journey forward, Now we will be create a very practical plugin which will decode the JWT token present in the request header under Proxy tab by creating a separate tab under proxy which will display the decoded JWT token present in the request.

## tl;dr
[Code](../../code/BurpExtenderChapter7)
In this chapter we will be creating a proxy tab extender plugin which will decode the JWT token present in the request header and output its decoded value on the GO. To implement such functionality we would need to implement `IMessageEditorTabFactory` interface and register it like we do normally.

Important stuff to remember : `IMessageEditorTabFactory` implementation function will returns a `IMessageEditorTab` instance which tell Burp what a new tab under Burp Proxy would look like.

### Step 1 : Implement `IMessageEditorTab` Interface
- This will
    - Tell Burp what to do in new tab.
    - be returned by the `IMessageEditorTabFactory`

This is how this `Tab` class would look like in abstract way. Stay with me, We will fill up the space, one by one.

```java
package burp;

import java.awt.*;

public class JWTDecodeTab implements IMessageEditorTab {

    private boolean editable;
    private ITextEditor txtInput;
    private byte[] currentMessage;
    private IBurpExtenderCallbacks callbacks;

    public JWTDecodeTab(IMessageEditorController controller, boolean editable) {
    }

    @Override public String getTabCaption() {
        return null;
    }

    @Override public Component getUiComponent() {
        return null;
    }

    @Override public boolean isEnabled(byte[] content, boolean isRequest) {
        return false;
    }

    @Override public void setMessage(byte[] content, boolean isRequest) {

    }

    @Override public byte[] getMessage() {
        return new byte[0];
    }

    @Override public boolean isModified() {
        return false;
    }

    @Override public byte[] getSelectedData() {
        return new byte[0];
    }
}
```
### Step 2 : Fill up constructor

```java
    public JWTDecodeTab(IMessageEditorController controller, boolean editable, IBurpExtenderCallbacks callbacks) {
        this.editable = editable;
        this.callbacks = callbacks;

        /*
         Create an instance of Burp's text editor, to display our JWT decode data.
         */
        txtInput = this.callbacks.createTextEditor();
        txtInput.setEditable(editable);
    }
```

### Step 3 : Other functions
Explanations are inline with functions.

```java
    /*
    This will set the name for this tab under Proxy.
     */
    @Override public String getTabCaption() {
        return "JWT Decode";
    }
```

```java
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
```

```java
    @Override public byte[] getMessage() {
        return currentMessage;
    }

    @Override public boolean isModified() {
        return txtArea.isTextModified();
    }

    @Override public byte[] getSelectedData() {
        return txtArea.getSelectedText();
    }
```

### Step 4 : Important decode function
Explanation Inline.
```java
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
```

And last but not the least, the main `BurpExtender` class, to bring everything to life.
```java
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

```
#### Test
- Send a Curl request with JWT token : `curl -XPOST -d "jwtToken=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJ1c2VyLWlkIjoiamRvZSIsImlhdCI6MTUxNjIzOTAyMn0.HQfUO7XHwp-Sx8oCQQBz90cGcvLI_43KdUNb4qzQ9Ag" http://example.com -x http://localhost:8080` through proxy.
- Check the plugin is decoding JWT Token.
    <p align=center>
        <image src="../../static/images/chapter7/file1.png" />
    </p>


### [Next: Burp Suite Extension - Create a Separate tab plugin : JWT Encode/Decode](series/Chapter8/README.md)