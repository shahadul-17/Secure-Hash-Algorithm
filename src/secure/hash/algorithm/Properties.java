package secure.hash.algorithm;

import java.util.Scanner;

public class Properties {
	
	private byte numberBaseOfData, numberOfInitialHashValues, numberOfRoundConstants,
		numberOfRounds, inputBytesInEachBlock, bufferMatrixRows;
	private short blockSize;
	
	public Properties(String secureHashAlgorithmFamily) throws Exception {
		load(secureHashAlgorithmFamily);
	}
	
	public byte getNumberBaseOfData() {
		return numberBaseOfData;
	}
	
	public byte getNumberOfInitialHashValues() {
		return numberOfInitialHashValues;
	}
	
	public byte getNumberOfRoundConstants() {
		return numberOfRoundConstants;
	}
	
	public byte getNumberOfRounds() {
		return numberOfRounds;
	}
	
	public byte getInputBytesInEachBlock() {
		return inputBytesInEachBlock;
	}
	
	public byte getBufferMatrixRows() {
		return bufferMatrixRows;
	}
	
	public short getBlockSize() {
		return blockSize;
	}
	
	private void load(String secureHashAlgorithmFamily) throws Exception {
		Scanner scanner = new Scanner(this.getClass().getResourceAsStream("/data/properties." + secureHashAlgorithmFamily));
		
		while (scanner.hasNextLine()) {
			int index;
			
			String line = scanner.nextLine();
			
			if ((index = line.indexOf('/')) > -1) {
				line = line.substring(0, index);
			}
			
			line = line.trim();
			
			if (line.startsWith("number-base-of-data")) {
				numberBaseOfData = Byte.parseByte(line.substring(line.indexOf('=') + 1));
			}
			else if (line.startsWith("number-of-initial-hash-values")) {
				numberOfInitialHashValues = Byte.parseByte(line.substring(line.indexOf('=') + 1));
			}
			else if (line.startsWith("number-of-round-constants")) {
				numberOfRoundConstants = Byte.parseByte(line.substring(line.indexOf('=') + 1));
			}
			else if (line.startsWith("number-of-rounds")) {
				numberOfRounds = Byte.parseByte(line.substring(line.indexOf('=') + 1));
			}
			else if (line.startsWith("input-bytes-in-each-block")) {
				inputBytesInEachBlock = Byte.parseByte(line.substring(line.indexOf('=') + 1));
			}
			else if (line.startsWith("buffer-matrix-rows")) {
				bufferMatrixRows = Byte.parseByte(line.substring(line.indexOf('=') + 1));
			}
			else if (line.startsWith("block-size")) {
				blockSize = Short.parseShort(line.substring(line.indexOf('=') + 1));
			}
		}
		
		scanner.close();
	}
	
}