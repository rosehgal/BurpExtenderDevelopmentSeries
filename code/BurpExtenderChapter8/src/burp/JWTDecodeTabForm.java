package burp;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.nio.IntBuffer;

import com.auth0.jwt.*;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

public class JWTDecodeTabForm {
    private JPanel basePanel;
    private JTextArea jwtTokenTextArea;
    private JTextArea headerFieldTextArea;
    private JButton decodeButton;
    private JButton encodeButton;
    private JTextArea payloadFieldTextArea;
    private JTextArea signatureFieldTextArea;
    private JTextArea jwtSecretTextArea;
    private JComboBox comboBox1;
    private JLabel jwtValidationErrorLabel;

    IBurpExtenderCallbacks callbacks;

    public JWTDecodeTabForm(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        decodeButton.addActionListener(new ActionListener() {
            @Override public void actionPerformed(ActionEvent actionEvent) {
                callbacks.issueAlert("Level 1");
                String jwtToken = jwtTokenTextArea.getText().trim();
                try {

                    /*
                    Use the algorithm with secret provided.
                     */
                    Algorithm algorithm = Algorithm.HMAC256(jwtSecretTextArea.getText().trim());
                    callbacks.issueAlert("Level 2");
                    /*
                    Reusable verifier instance
                     */
                    JWTVerifier verifier = JWT.require(algorithm)
                                              .withIssuer("auth0")
                                              .build();
                    callbacks.issueAlert("Level 3");

                    DecodedJWT jwt = verifier.verify(jwtToken);
                    callbacks.issueAlert("Level 4");

                    headerFieldTextArea.setText(jwt.getHeader());
                    callbacks.issueAlert("Level 5");

                    payloadFieldTextArea.setText(jwt.getPayload());

                } catch (Exception exception){
                    callbacks.issueAlert("Exception is there.");
                    callbacks.issueAlert(exception.getMessage());
                }
            }
        });
    }

    public Component getFrame(){
        return this.basePanel;
    }
}
