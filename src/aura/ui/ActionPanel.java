package aura.ui;

import javax.swing.JPanel;

import burp.IBurpExtenderCallbacks;
import burp.ITextEditor;

@SuppressWarnings("serial")
public class ActionPanel extends JPanel{
	public ITextEditor textEditor;
	
	public ActionPanel(IBurpExtenderCallbacks cb){
		this.textEditor = cb.createTextEditor();
	}
	
	public byte[] getSelectedText(){
		return textEditor.getSelectedText();
	}
}
