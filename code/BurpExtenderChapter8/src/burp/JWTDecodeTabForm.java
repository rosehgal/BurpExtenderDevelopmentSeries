package burp;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;


public class JWTDecodeTabForm {
    private JPanel basePanel;
    private JTextArea jwtTokenTextArea;
    private JTextArea headerFieldTextArea;
    private JButton decodeButton;
    private JButton encodeButton;
    private JTextArea payloadFieldTextArea;
    private JTextArea jwtSecretTextArea;
    private JComboBox comboBox1;
    private JLabel jwtValidationErrorLabel;

    IBurpExtenderCallbacks callbacks;
    IExtensionHelpers helpers;

    public JWTDecodeTabForm(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        decodeButton.addActionListener(new ActionListener() {
            @Override public void actionPerformed(ActionEvent actionEvent) {
                String jwtToken = jwtTokenTextArea.getText().trim();
                try {
                    List<String> jwtTokenParts = Arrays.asList(jwtToken.split(Pattern.quote(".")));

                    headerFieldTextArea.setText(helpers.bytesToString(helpers.base64Decode(jwtTokenParts.get(0))));
                    payloadFieldTextArea.setText(helpers.bytesToString(helpers.base64Decode(jwtTokenParts.get(1))));

                }catch (Exception e){
                    /*
                    For pupup, display error in PopUp
                     */
                    JOptionPane.showConfirmDialog(basePanel, e.getMessage(), "Error", JOptionPane.OK_CANCEL_OPTION);
                }
            }
        });
        encodeButton.addActionListener(new ActionListener() {
            @Override public void actionPerformed(ActionEvent actionEvent) {
                try{
                Mac sha512Hmac;
                String secret = jwtSecretTextArea.getText();

                final byte[] byteKey = secret.getBytes(StandardCharsets.UTF_8);
                sha512Hmac = Mac.getInstance("HmacSHA512");
                SecretKeySpec keySpec = new SecretKeySpec(byteKey, "HmacSHA512");
                sha512Hmac.init(keySpec);

                String partialJwt = helpers.base64Encode(headerFieldTextArea.getText()) +
                        "." +
                        helpers.base64Encode(payloadFieldTextArea.getText());

                byte[] macData = sha512Hmac.doFinal(partialJwt.getBytes(StandardCharsets.UTF_8));

                jwtTokenTextArea.setText(partialJwt + '.' + helpers.base64Encode(helpers.bytesToString(macData)));

                }catch (Exception e){
                    JOptionPane.showConfirmDialog(basePanel, e.getMessage(), "Error", JOptionPane.OK_CANCEL_OPTION);
                }
            }
        });
    }

    public Component getFrame(){
        return this.basePanel;
    }
}
