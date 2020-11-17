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
