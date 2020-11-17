# Use Case : Plugin to create Intruder payload processing

This chapter is short post to create a plugin for a use case. The plugin will process the payload from the Intruder and will execute the payload after processing. To implement this we need to implement `IIntruderPayloadProcessor`. Then the process is fairly simple as we have done in our previous cases. Create a class which implements this `IIntruderPayloadProcessor` and then register the instance of the class to `IBurpExtender.callbacks.registerIntruderPayloadProcessor()`.

`IIntruderPayloadProcessor` interface contains two method signatures of the following structure, these will be overridden in the implementer class:

- String `getProcessorName()`: This will be provide name of the payload processor in the Burp Suite UI.

- byte[] `processPayload(byte[] currentPayload, byte[] originalPayload, byte[] baseValue)`: This is the responsible function for payload processing, the processed payload should return as byte array. We can utilise helpers to convert String to `byte[]` by invoking `stringToBytes()`; to achieve the opposite `bytestoString()` can be used from the `callbacks.getHelpers()`
    - `currentPayload` - The value of the payload to be processed.
    - `originalPayload` - The value of the original payload prior to processing by any already-applied processing rules.
    - `baseValue` - The base value of the payload position, which will be replaced with the current payload.

Look at this self explanatory code.
```java
/*
IntruderProcessor.java
*/
package burp;

public class IntruderPayloadProcessor implements IIntruderPayloadProcessor{

    IExtensionHelpers helpers;

    public IntruderPayloadProcessor(IBurpExtenderCallbacks callbacks){
        /*
            We can use the helpers string to byte array method as processPayload need to return byte[]
         */
        helpers = callbacks.getHelpers();
    }

    @Override public String getProcessorName() {
        /*
            This name will be shown in the Burp Suite Intruder UI as processor name.
         */
        return "Base64 Processor";
    }

    @Override public byte[] processPayload(byte[] currentPayload, byte[] originalPayload, byte[] baseValue) {
        if(currentPayload != null){
            return helpers.stringToBytes(helpers.base64Encode(currentPayload));
        }
        return null;
    }
}

```

Tell burp that you have payload processor.
```java
/*
BurpExtender.java
*/

package burp;

public class BurpExtender implements IBurpExtender {
    @Override public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("Intruder Processing");
        callbacks.issueAlert("Plugin loaded");

        // Notice this.
        callbacks.registerIntruderPayloadProcessor(new IntruderPayloadProcessor(callbacks));
    }
}

```
`Build` the artifact, load it in Burp.

<p align=center>
<img src=../../static/images/Chapter4/file1.png width=90%>
</p>

In the item you can see that, `IntruderProcessor` is coming up.

Now this Payload processor will pop up in Intruder, payload processor like follows.

<p align=center>
<img src=../../static/images/Chapter4/file2.png width=90%>
</p>

The name you have entered for Payload processor in the implementing class will come under drop down. Since I entered `Base64 Processor`, it is showing as it is.

Run it and check the payloads are getting converted to `base64` by our processor and are executed like wise.

<p align=center>
<img src=../../static/images/Chapter4/file3.png width=90%>
</p>