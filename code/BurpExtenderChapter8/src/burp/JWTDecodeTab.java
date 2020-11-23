package burp;

import java.awt.*;

public class JWTDecodeTab implements ITab {
  IBurpExtenderCallbacks callbacks;

  public JWTDecodeTab(IBurpExtenderCallbacks callbacks) {
    this.callbacks = callbacks;
  }

  @Override public String getTabCaption() {
    return "JWT Decode/Encode";
  }

  @Override public Component getUiComponent() {
    return new JWTDecodeTabForm(callbacks).getFrame();
  }
}
