package paradise;

import ghidra.framework.plugintool.util.PluginPackage;
import ghidra.framework.plugintool.util.PluginStatus;

public class ParadisePluginPackage extends PluginPackage {
	public static final String NAME = "Paradise";

	public ParadisePluginPackage() {
		super(NAME, null,
			"Paradise decompiler workflow actions backed by Ghidra's native decompiler.",
			FEATURE_PRIORITY);
	}

	@Override
	public PluginStatus getActivationLevel() {
		return PluginStatus.STABLE;
	}
}
