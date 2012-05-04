package Utils;

import java.util.Scanner;

public class PasswordUtils {

	public static String readInPassword(String title) {
		System.out.print("Please type password for "+title);
		Scanner sc = new Scanner(System.in);
		return sc.nextLine();
	}
}
