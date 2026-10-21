// ReverseAI's fixed Ghidra query (reviewed code baked into the image; requests cannot choose scripts).
// Arguments: <output JSON path> <max_functions> <decompile> <entry file offset or -1> <decompile seconds> <assembly>
// <max_instructions>.
// Writes what Ghidra reports, as plain JSON: memory blocks, functions (address order, at most MAX_FUNCTIONS; size is
// the span from the entry to the last body byte, decision m3a-function-span), the calls and the other references
// (with their reference-type flags) from the instructions of the first max_functions file-backed executable
// functions, pseudocode for the entry-point function and then the largest of those, and, in the same order, the
// first instructions of `assembly` of them (M3c). The Python worker checks what the bytes can confirm (each anchor's
// file offset, bytes and memory-block mapping, one rebase delta, bounds and order) and drops or refuses the rest;
// names, sizes, call and reference targets, reference types, instruction texts and pseudocode remain Ghidra's
// interpretation, reported as derived and never as verified.
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
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;

public class ReverseAIQuery extends GhidraScript {
	private static final int MAX_FUNCTIONS = 4096;
	private static final int MAX_CALLS_PER_FUNCTION = 1024;
	private static final int MAX_REFS_PER_FUNCTION = 1024;
	private static final int MAX_BODY_INSTRUCTIONS = 1000000;
	private static final int MAX_LOCATION = 4096;
	private static final int MAX_TEXT = 65536;
	// The same rule as ReverseAIOptions: the worker refuses the run if any of these is still on.
	private static final Pattern OFF = Pattern.compile("(?i).*(pdb|dwarf|swift).*");

	private Memory memory;

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length != 7) {
			throw new IllegalArgumentException("ReverseAIQuery arguments");
		}
		int maxFunctions = Integer.parseInt(args[1]);
		int decompile = Integer.parseInt(args[2]);
		long entryOffset = Long.parseLong(args[3]);
		long deadline = System.currentTimeMillis() + 1000L * Integer.parseInt(args[4]);
		int assembly = Integer.parseInt(args[5]);
		int maxInstructions = Integer.parseInt(args[6]);
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
			long size = span(function);
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
			out.append("],\"refs\":[");
			if (anchored) {
				appendRefs(out, function);
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
			int bySize = Long.compare(span(b), span(a));
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
		out.append("],\"assembly\":[");
		first = true;
		for (Function function : order.subList(0, Math.min(Math.max(assembly, 0), order.size()))) {
			out.append(first ? "" : ",");
			appendInstructions(out, function, maxInstructions);
			first = false;
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

	/** Every non-call memory reference from the function's instructions, with Ghidra's reference-type flags. */
	private void appendRefs(StringBuilder out, Function function) throws Exception {
		boolean first = true;
		int refs = 0;
		for (Instruction instruction : currentProgram.getListing().getInstructions(function.getBody(), true)) {
			for (Reference reference : instruction.getReferencesFrom()) {
				Address target = reference.getToAddress();
				RefType type = reference.getReferenceType();
				if (refs == MAX_REFS_PER_FUNCTION || !target.isMemoryAddress() || type.isCall()) {
					continue;
				}
				refs++;
				out.append(first ? "" : ",").append("{\"address\":").append(instruction.getAddress().getOffset())
					.append(",\"length\":").append(instruction.getLength())
					.append(",\"file_offset\":").append(fileOffset(instruction.getAddress()))
					.append(",\"bytes\":").append(quote(toHex(instruction.getBytes())))
					.append(",\"to\":").append(target.getOffset())
					.append(",\"to_file_offset\":").append(fileOffset(target))
					.append(",\"to_name\":").append(quote(nameAt(target)))
					.append(",\"type\":").append(quote(type.getName()))
					.append(",\"flow\":").append(type.isFlow())
					.append(",\"jump\":").append(type.isJump())
					.append(",\"read\":").append(type.isRead())
					.append(",\"write\":").append(type.isWrite())
					.append(",\"data\":").append(type.isData())
					.append(",\"inside\":").append(function.getBody().contains(target)).append("}");
				first = false;
			}
		}
	}

	/** The function's instructions from its entry in address order, at most maxInstructions, and how many it has. */
	private void appendInstructions(StringBuilder out, Function function, int maxInstructions) throws Exception {
		Address entry = function.getEntryPoint();
		out.append("{\"entry\":").append(entry.getOffset()).append(",\"instructions\":[");
		boolean first = true;
		int listed = 0;
		int count = 0;
		for (Instruction instruction : currentProgram.getListing().getInstructions(function.getBody(), true)) {
			if (count == MAX_BODY_INSTRUCTIONS) {
				break;
			}
			count++;
			if (listed == maxInstructions || instruction.getAddress().compareTo(entry) < 0) {
				continue;
			}
			listed++;
			out.append(first ? "" : ",").append("{\"address\":").append(instruction.getAddress().getOffset())
				.append(",\"length\":").append(instruction.getLength())
				.append(",\"file_offset\":").append(fileOffset(instruction.getAddress()))
				.append(",\"bytes\":").append(quote(toHex(instruction.getBytes())))
				.append(",\"text\":").append(quote(instruction.toString())).append("}");
			first = false;
		}
		out.append("],\"count\":").append(count).append("}");
	}

	/** Entry to the last byte of the body: a body with gaps keeps the calls in its later ranges. */
	private static long span(Function function) {
		Address entry = function.getEntryPoint();
		Address last = function.getBody().getMaxAddress();
		return last == null || last.compareTo(entry) < 0 ? 1 : last.subtract(entry) + 1;
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
