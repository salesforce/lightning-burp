package aura.ui;

import burp.IBurpExtenderCallbacks;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;

public class AuraTabFactory implements IMessageEditorTabFactory {
	private IBurpExtenderCallbacks callbacks;
	
	public AuraTabFactory(IBurpExtenderCallbacks callbacks){
		this.callbacks = callbacks;
	}
	
	@Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		return new AuraTab(controller, editable,this.callbacks);
	}

}
