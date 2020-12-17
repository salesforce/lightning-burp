package aura.ui;

import java.awt.BorderLayout;

import com.fasterxml.jackson.core.JsonProcessingException;

import aura.ActionResponse;
import burp.IBurpExtenderCallbacks;

@SuppressWarnings("serial")
public class ActionResponsePanel extends ActionPanel {
	private IBurpExtenderCallbacks callbacks;
	
	public ActionResponsePanel(IBurpExtenderCallbacks cb, ActionResponse response){
		super(cb);
		this.callbacks = cb;
		this.setLayout(new BorderLayout());
		
		this.textEditor = this.callbacks.createTextEditor();
		this.textEditor.setEditable(false);
		try {
			this.textEditor.setText(response.getResponseString().getBytes());
		} catch (JsonProcessingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			this.textEditor.setText("Invalid JSON".getBytes());
		}
		add(this.textEditor.getComponent());
		
		callbacks.customizeUiComponent(this);
	}
}
