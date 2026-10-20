// ReverseAI's fixed Ghidra query (reviewed code baked into the image; requests cannot choose scripts).
// Arguments: <output JSON path> <max_functions> <decompile> <entry file offset or -1> <decompile seconds>.
// Writes memory blocks, functions (address order, at most MAX_FUNCTIONS), the calls inside the first
// max_functions file-backed executable functions, and pseudocode for the entry-point function and then the
// largest of those, all as plain JSON. The Python worker re-checks and maps every value; this script decides
// nothing that reaches the host unchecked.
//@category ReverseAI

import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.database.mem.AddressSourceInfo;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;

public class ReverseAIQuery extends GhidraScript {
	private static final int MAX_FUNCTIONS = 4096;
	private static final int MAX_CALLS_PER_FUNCTION = 1024;
	private static final int MAX_LOCATION = 4096;
	private static final int MAX_TEXT = 65536;
	// The same rule as ReverseAIOptions: the worker refuses the run if any of these is still on.
	private static final Pattern OFF = Pattern.compile("(?i).*(pdb|dwarf|swift).*");

	private Memory memory;

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length != 5) {
			throw new IllegalArgumentException("ReverseAIQuery arguments");
		}
		int maxFunctions = Integer.parseInt(args[1]);
		int decompile = Integer.parseInt(args[2]);
		long entryOffset = Long.parseLong(args[3]);
		long deadline = System.currentTimeMillis() + 1000L * Integer.parseInt(args[4]);
		memory = currentProgram.getMemory();

		StringBuilder out = new StringBuilder("{\"format\":").append(quote(currentProgram.getExecutableFormat()))
			.append(",\"options_off\":{");
		boolean first = true;
		for (Map.Entry<String, String> option : getCurrentAnalysisOptionsAndValues(currentProgram).entrySet()) {
			if (OFF.matcher(option.getKey()).matches()) {
				out.append(first ? "" : ",").append(quote(option.getKey())).append(":").append(quote(option.getValue()));
				first = false;
			}
		}
		out.append("},\"blocks\":[");
		first = true;
		for (MemoryBlock block : memory.getBlocks()) {
			if (!block.isLoaded()) {
				continue; // non-loaded blocks (section headers, .symtab, ...) are not part of the program's address space
			}
			out.append(first ? "" : ",").append("{\"name\":").append(quote(block.getName()))
				.append(",\"start\":").append(block.getStart().getOffset())
				.append(",\"size\":").append(block.getSize())
				.append(",\"execute\":").append(block.isExecute())
				.append(",\"initialized\":").append(block.isInitialized())
				.append(",\"file_offset\":").append(blockFileOffset(block)).append("}");
			first = false;
		}

		List<Function> selected = new ArrayList<>();
		out.append("],\"functions\":[");
		first = true;
		int count = 0;
		for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
			if (function.isExternal() || count == MAX_FUNCTIONS) {
				continue;
			}
			count++;
			Address entry = function.getEntryPoint();
			long size = function.getBody().getNumAddresses();
			long offset = fileOffset(entry);
			MemoryBlock block = memory.getBlock(entry);
			boolean anchored = offset >= 0 && block != null && block.isExecute() && block.isInitialized()
				&& selected.size() < maxFunctions;
			out.append(first ? "" : ",").append("{\"name\":").append(quote(function.getName()))
				.append(",\"entry\":").append(entry.getOffset())
				.append(",\"size\":").append(size)
				.append(",\"file_offset\":").append(offset)
				.append(",\"anchored\":").append(anchored)
				.append(",\"bytes\":").append(quote(anchored ? hex(entry, block, size) : ""))
				.append(",\"calls\":[");
			if (anchored) {
				selected.add(function);
				appendCalls(out, function);
			}
			out.append("]}");
			first = false;
		}

		out.append("],\"pseudocode\":[");
		List<Function> order = new ArrayList<>();
		for (Function function : selected) {
			if (fileOffset(function.getEntryPoint()) == entryOffset) {
				order.add(function);
			}
		}
		List<Function> rest = new ArrayList<>(selected);
		rest.removeAll(order);
		rest.sort((a, b) -> {
			int bySize = Long.compare(b.getBody().getNumAddresses(), a.getBody().getNumAddresses());
			return bySize != 0 ? bySize : a.getEntryPoint().compareTo(b.getEntryPoint());
		});
		order.addAll(rest);
		first = true;
		if (decompile > 0 && !order.isEmpty()) {
			DecompInterface decompiler = new DecompInterface();
			try {
				decompiler.setOptions(new DecompileOptions());
				decompiler.openProgram(currentProgram);
				for (Function function : order.subList(0, Math.min(decompile, order.size()))) {
					int left = (int) ((deadline - System.currentTimeMillis()) / 1000);
					if (left < 1) {
						break;
					}
					DecompileResults result = decompiler.decompileFunction(function, Math.min(left, 15), monitor);
					if (result == null || !result.decompileCompleted() || result.getDecompiledFunction() == null) {
						continue;
					}
					String text = result.getDecompiledFunction().getC();
					if (text.length() > MAX_TEXT) {
						text = text.substring(0, MAX_TEXT);
					}
					out.append(first ? "" : ",").append("{\"entry\":").append(function.getEntryPoint().getOffset())
						.append(",\"text\":").append(quote(text)).append("}");
					first = false;
				}
			}
			finally {
				decompiler.dispose();
			}
		}
		out.append("]}");
		try (Writer writer = new OutputStreamWriter(new FileOutputStream(args[0]), StandardCharsets.UTF_8)) {
			writer.write(out.toString());
		}
	}

	private void appendCalls(StringBuilder out, Function function) throws Exception {
		boolean first = true;
		int calls = 0;
		for (Instruction instruction : currentProgram.getListing().getInstructions(function.getBody(), true)) {
			if (calls == MAX_CALLS_PER_FUNCTION || !instruction.getFlowType().isCall()) {
				continue;
			}
			Address target = null;
			for (Address flow : instruction.getFlows()) {
				if (flow.isMemoryAddress()) {
					target = flow;
					break;
				}
			}
			if (target == null) {
				for (Reference reference : instruction.getReferencesFrom()) {
					if (reference.getToAddress().isMemoryAddress()) {
						target = reference.getToAddress();
						break;
					}
				}
			}
			if (target == null) {
				continue;
			}
			calls++;
			out.append(first ? "" : ",").append("{\"address\":").append(instruction.getAddress().getOffset())
				.append(",\"length\":").append(instruction.getLength())
				.append(",\"file_offset\":").append(fileOffset(instruction.getAddress()))
				.append(",\"bytes\":").append(quote(toHex(instruction.getBytes())))
				.append(",\"to\":").append(target.getOffset())
				.append(",\"to_file_offset\":").append(fileOffset(target))
				.append(",\"to_name\":").append(quote(nameAt(target))).append("}");
			first = false;
		}
	}

	private String nameAt(Address address) {
		Function function = getFunctionAt(address);
		if (function != null) {
			return function.getName();
		}
		Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(address);
		return symbol == null ? "" : symbol.getName();
	}

	private long fileOffset(Address address) {
		AddressSourceInfo info = memory.getAddressSourceInfo(address);
		return info == null ? -1 : info.getFileOffset();
	}

	private long blockFileOffset(MemoryBlock block) {
		List<MemoryBlockSourceInfo> sources = block.getSourceInfos();
		if (sources.size() != 1 || sources.get(0).getFileBytes().isEmpty() || sources.get(0).getLength() != block.getSize()) {
			return -1;
		}
		return sources.get(0).getFileBytesOffset();
	}

	private String hex(Address entry, MemoryBlock block, long size) throws Exception {
		if (block == null || !block.isInitialized()) {
			return "";
		}
		long left = block.getEnd().subtract(entry) + 1;
		byte[] bytes = new byte[(int) Math.max(0, Math.min(Math.min(size, MAX_LOCATION), left))];
		memory.getBytes(entry, bytes);
		return toHex(bytes);
	}

	private static String toHex(byte[] bytes) {
		StringBuilder text = new StringBuilder(bytes.length * 2);
		for (byte value : bytes) {
			text.append(String.format("%02x", value & 0xff));
		}
		return text.toString();
	}

	private static String quote(String value) {
		StringBuilder text = new StringBuilder("\"");
		for (int i = 0; i < value.length(); i++) {
			char c = value.charAt(i);
			if (c == '"' || c == '\\') {
				text.append('\\').append(c);
			}
			else if (c < 0x20 || c > 0x7e) {
				text.append(String.format("\\u%04x", (int) c));
			}
			else {
				text.append(c);
			}
		}
		return text.append('"').toString();
	}
}
