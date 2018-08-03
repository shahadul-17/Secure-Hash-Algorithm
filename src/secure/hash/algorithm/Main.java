/*
 * 
 * GitHub repository -> https://github.com/shahadul-17/Secure-Hash-Algorithm.git
 * 
 */

package secure.hash.algorithm;

import java.io.File;
import java.io.PrintWriter;

public class Main {
	
	public static void main(String[] args) {
		String[] defaultArguments = { "SHA-1", "-t", "" };		// default parameters...
		
		SecureHashAlgorithm secureHashAlgorithm = null;
		
		if (args.length != defaultArguments.length) {
			args = new String[defaultArguments.length];
			
			System.arraycopy(defaultArguments, 0, args, 0, defaultArguments.length);
		}
		
		args[0] = args[0].toUpperCase();
		
		try {
			byte secureHashAlgorithmFamily = -1;
			
			if (args[0].equals("SHA-1")) {
				secureHashAlgorithmFamily = SecureHashAlgorithm.SHA_1;
			}
			else if (args[0].equals("SHA-2")) {
				secureHashAlgorithmFamily = SecureHashAlgorithm.SHA_2;
			}
			
			secureHashAlgorithm = new SecureHashAlgorithm(secureHashAlgorithmFamily);
		}
		catch (Exception exception) {
			if (exception.getMessage() == null) {
				System.out.println("error: an unknown error occured");
			}
			else {
				System.out.println("error: " + exception.getMessage());
			}
			
			return;
		}
		
		if (args[1].equalsIgnoreCase("-t")) {		// text mode...
			secureHashAlgorithm.generateHash(args[2]);
		}
		else if (args[1].equalsIgnoreCase("-f")) {		// file mode...
			try {
				secureHashAlgorithm.generateHash(new File(args[2]));
			}
			catch (Exception exception) {
				System.out.println("error: could not open the file '" + args[2] + "'");
				
				return;
			}
		}
		else {
			System.out.println("error: please provide '-t' (for text mode) or '-f' (for file mode) without the quotes as second argument");
			
			return;
		}
		
		try {
			System.out.println(args[0] + ": " + secureHashAlgorithm);
			
			PrintWriter printWriter = new PrintWriter(new File("output-" + args[0] + ".txt"));		// writing to output file...
			printWriter.print(secureHashAlgorithm);
			printWriter.flush();
			printWriter.close();
		}
		catch (Exception exception) {
			exception.printStackTrace();
		}
	}
	
}