using System;
using System.Collections.Generic;
using System.Text;
using System.IO;

class Program
{
    static void Main(string[] args)
    {
        Console.Write("Enter the number of license keys to generate: ");
        int numberOfKeys;
        while (!int.TryParse(Console.ReadLine(), out numberOfKeys) || numberOfKeys <= 0)
        {
            Console.Write("Invalid input. Please enter a positive integer: ");
        }

        List<string> validLicenseKeys = GenerateValidLicenseKeys(numberOfKeys);

        Console.WriteLine("\nGenerated License Keys:");
        foreach (var key in validLicenseKeys)
        {
            Console.WriteLine(key);
        }

        Console.Write("\nDo you want to save the keys to a file? (y/n): ");
        string saveChoice = Console.ReadLine();
        if (saveChoice.Equals("y", StringComparison.OrdinalIgnoreCase))
        {
            SaveKeysToFile(validLicenseKeys);
            Console.WriteLine("Keys have been saved to keys.txt");
        }
    }

    static List<string> GenerateValidLicenseKeys(int numberOfKeys)
    {
        List<string> validKeys = new List<string>();
        for (int i = 0; i < numberOfKeys; i++)
        {
            validKeys.Add(GenerateValidLicenseKey());
        }
        return validKeys;
    }

    static string GenerateValidLicenseKey()
    {
        string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        Random random = new Random();

        StringBuilder key = new StringBuilder();
        for (int i = 0; i < 3; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                key.Append(chars[random.Next(chars.Length)]);
            }
            key.Append('-');
        }

        // Generate the last part of the key
        string lastPart = "";
        int sum = 0;
        for (int j = 0; j < 4; j++)
        {
            char c = chars[random.Next(chars.Length)];
            lastPart += c;
            if (char.IsDigit(c))
            {
                sum += c - '0';
            }
        }

        // Encode license key to Base64
        string base64EncodedKey = Convert.ToBase64String(Encoding.UTF8.GetBytes(key.ToString() + lastPart));

        // Calculate the sum of all numeric characters in the base64 encoded string
        int base64Sum = 0;
        foreach (char c in base64EncodedKey)
        {
            if (char.IsDigit(c))
            {
                base64Sum += c - '0';
            }
        }

        // Total sum of numeric values
        int totalSum = base64Sum + sum;

        // Ensure the total sum is in the range 0 to 20
        if (totalSum > 20)
        {
            lastPart = AdjustLastPart(lastPart, 20 - base64Sum, sum, random);
        }

        key.Append(lastPart);
        return key.ToString();
    }

    static string AdjustLastPart(string lastPart, int maxAllowedSum, int currentSum, Random random)
    {
        // Adjust the last part to ensure the sum is within the range
        StringBuilder adjustedPart = new StringBuilder(lastPart);
        int maxDifference = maxAllowedSum - currentSum;
        int index = 3;

        while (maxDifference < 0 && index >= 0)
        {
            char c = adjustedPart[index];
            if (char.IsDigit(c))
            {
                int digitValue = c - '0';
                int newDigitValue = Math.Max(0, digitValue + maxDifference);

                adjustedPart[index] = (char)(newDigitValue + '0');
                maxDifference -= (newDigitValue - digitValue);
            }
            index--;
        }

        return adjustedPart.ToString();
    }

    static void SaveKeysToFile(List<string> keys)
    {
        using (StreamWriter writer = new StreamWriter("keys.txt"))
        {
            foreach (var key in keys)
            {
                writer.WriteLine(key);
            }
        }
    }
}
