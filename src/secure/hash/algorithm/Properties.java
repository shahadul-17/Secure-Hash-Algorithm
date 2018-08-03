package secure.hash.algorithm;

import java.util.Scanner;

public class Properties {
	
	private byte numberBaseOfData, numberOfInitialHashValues, numberOfRoundConstants,
		numberOfRounds, inputBytesInEachBlock, maximumLengthBytes, bufferMatrixRows;
	private short blockSize;
	
	public Properties(byte secureHashAlgorithmFamily) throws Exception {
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
	
	public byte getMaximumLengthBytes() {
		return maximumLengthBytes;
	}
	
	public byte getBufferMatrixRows() {
		return bufferMatrixRows;
	}
	
	public short getBlockSize() {
		return blockSize;
	}
	
	private void load(byte secureHashAlgorithmFamily) throws Exception {
		Scanner scanner = new Scanner(this.getClass().getResourceAsStream("/data/properties.SHA-" + (secureHashAlgorithmFamily + 1)));
		
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
			else if (line.startsWith("maximum-length-bytes")) {
				maximumLengthBytes = Byte.parseByte(line.substring(line.indexOf('=') + 1));
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