package burp;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;

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
                callbacks.issueAlert("Level 1");
                String jwtToken = jwtTokenTextArea.getText().trim();
                try {
                    List<String> jwtTokenParts = Arrays.asList(jwtToken.split(Pattern.quote(".")));

                    headerFieldTextArea.setText(helpers.bytesToString(helpers.base64Decode(jwtTokenParts.get(0))));
                    payloadFieldTextArea.setText(helpers.bytesToString(helpers.base64Decode(jwtTokenParts.get(1))));

                }catch (Exception e){
                    JOptionPane.showConfirmDialog(basePanel, e.getMessage(), "Error", 0);
                }
            }
        });
    }

    public Component getFrame(){
        return this.basePanel;
    }
}
