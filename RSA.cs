using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace RSA
{
    public class RSA
    {
        private ulong publicKey, secretKey, N;
        public RSA(ulong publicKey, ulong secretKey, ulong N)
        {
            this.publicKey = publicKey;
            this.secretKey = secretKey;
            this.N = N;
        }
        
        public ulong Encode(ulong num)
        {
            return modPow(num, publicKey, N);
        }

        public ulong Decode(ulong num)
        {
            return modPow(num, secretKey, N);
        }

        public void EncodeFile(FileStream mFile, FileStream cFile)
        {
            BinaryReader reader = new BinaryReader(mFile);
            BinaryWriter writer = new BinaryWriter(cFile);
            //size of block in bits to encode
            int bytesToRead = sizeBlock(N);
            //read the bytes here
            byte[] bytesToEncode;
            while ((bytesToEncode = reader.ReadBytes(bytesToRead)).Length > 0)
            {
                #region Преобразование массива байт в строку
                String stringWithBits = ""; //string with bits to encrypt
                for (int i = 0; i < bytesToEncode.Length; i++)
                {
                    String strBitsOfByte = Convert.ToString(bytesToEncode[i], 2); // bits of each byte
                    int len = strBitsOfByte.Length;
                    if (len < 8) //add zeroes to beginning
                    {
                        String zero = new String('0', 8 - len);
                        strBitsOfByte = zero + strBitsOfByte;
                    }
                    stringWithBits += strBitsOfByte;
                }
                #endregion

                #region Считывание bytesToRead символов из строки и шифрование их с помощью RSA c последующей записью в виде UInt64
                for (int i = 0; i < stringWithBits.Length; i += bytesToRead)
                {
                    String strBlock;
                    //for the last block
                    if (i + bytesToRead > stringWithBits.Length)
                        strBlock = stringWithBits.Substring(i, stringWithBits.Length - i);
                    else
                        strBlock = stringWithBits.Substring(i, bytesToRead);
                    ulong numBlock = Convert.ToUInt64(strBlock, 2);
                    numBlock = Encode(numBlock);
                    writer.Write(numBlock);
                }
                #endregion
            }
            reader.Close();
            writer.Close();
        }

        public void DecodeFile(FileStream cFile, FileStream mFile)
        {
            BinaryReader reader = new BinaryReader(cFile);
            BinaryWriter writer = new BinaryWriter(mFile);
            int bytesToRead = sizeBlock(N) * 8;
            byte[] bytesToDecrypt;
            string stringWithBits = "";
            while ((bytesToDecrypt = reader.ReadBytes(bytesToRead)).Length > 0)
            {
                #region Получение UInt64 из массива байтов
                for (int i = 0; i < bytesToDecrypt.Length / 8; i++)
                {
                    ulong numBlock = BitConverter.ToUInt64(bytesToDecrypt, i * 8);
                    numBlock = Decode(numBlock);
                    #region Преобразование numblock в строчку
                    string bitsToAdd = Convert.ToString((long)numBlock, 2);
                    int slen = bitsToAdd.Length;
                    if (!(i == bytesToDecrypt.Length / 8 - 1 && cFile.Length == cFile.Position))
                    { 
                        //в случае если размер строки меньше bytesToRead символов
                        if (slen < bytesToRead / 8)
                        {
                            String zero = new String('0',bytesToRead / 8 - slen);
                            bitsToAdd = zero + bitsToAdd;
                        }
                        else if (slen > bytesToRead / 8)
                        {
                            bitsToAdd = bitsToAdd.Substring(0, bytesToRead / 8);
                        }
                    }
                    stringWithBits += bitsToAdd;
                    #endregion
                }
                for (int i = 0; i < stringWithBits.Length; i += 8)
                {
                    byte b;
                    if (stringWithBits.Length - i < 8)
                    {
                        if (cFile.Position == cFile.Length)
                            b = Convert.ToByte(stringWithBits.Substring(i, stringWithBits.Length - i), 2);
                        else
                        {
                            stringWithBits = stringWithBits.Substring(i, stringWithBits.Length - i);
                            break;
                        }
                    }
                    else
                        b = Convert.ToByte(stringWithBits.Substring(i, 8), 2);
                    writer.Write(b);
                }
                if (stringWithBits.Length % 8 == 0)
                    stringWithBits = "";
                #endregion
            }
            reader.Close();
            writer.Close();
        }

        //find max acceptable size of block 
        public static ushort sizeBlock(ulong N)
        {
            ulong one = (ulong)1 << 63;
            int i = 0;
            for (; i < 64; i++)
            {
                if ((N & one) != 0)
                    break;
                one >>= 1;
            }
            return (ushort)(63 - i);
        }
        //check whether a numbers are comprime
        public static bool isCoprime(ulong a, ulong b)
        {
            if (euclid(a, b) == 1)
                return true;
            return false;
        }
        //check whether a number is prime
        public static bool isPrime(ulong number)
        {
            ulong sqrtNum = Convert.ToUInt64(Math.Sqrt(Convert.ToDouble(number)));
            for (ulong i = 2; i <= sqrtNum; i++)
            {
                if (number % i == 0)
                    return false;
            }
            return true;
        }
        //алгоритм евклида
        public static ulong euclid(ulong a, ulong b)
        {
            if (b == 0)
                return a;
            return euclid(b, a % b);
        }
        //extended euclid algorithm
        public static ulong extendedEuclid(ulong a, ulong b, out long x, out long y)
        {
            if (a == 0)
            {
                x = 0;
                y = 1;
                return b;
            }
            long x1, y1;
            ulong d = extendedEuclid(b % a, a, out x1, out y1);
            x = y1 - (long)(b / a) * x1;
            y = x1;
            return d;
        }
        //find multiplicative inverse
        public static ulong mulInverse(ulong num, ulong mod)
        {
            long x, y;
            extendedEuclid(num, mod, out x, out y);
            if (x < 0)
                x += (long)mod;
            return (ulong)x;
        }
        //power of number in finite field
        public static ulong modPow(ulong num, ulong degree, ulong mod)
        {
            return (degree == 0) ? 1 : (((degree & 1) != 0) ? num : 1) * modPow((num * num) % mod, degree / 2, mod) % mod;
        }
    }
}
