using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Native;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables.Rows;
using AsmResolver.PE.File.Headers;
using System.Security.Cryptography;
using System.Text;
using UnmanagedString;
using MethodDefinition = AsmResolver.DotNet.MethodDefinition;
using ModuleDefinition = AsmResolver.DotNet.ModuleDefinition;

namespace SecureStringHandler
{
    public static class StringObfuscator
    {
        private static readonly byte[] Key = GenerateSecureKey(); // Generate a secure key for AES encryption

        public static void Main(string[] args)
        {
            try
            {
                // Check if the user provided the required argument
                if (args.Length != 1)
                {
                    Logger.Error("Usage: SecureStringHandler.exe <path to assembly>");
                    return; // Exit if no argument is provided
                }

                var targetAssemblyPath = args[0];

                // Ensure the specified file exists
                if (!File.Exists(targetAssemblyPath))
                {
                    Logger.Error($"File not found: {targetAssemblyPath}");
                    return; // Exit if the file doesn't exist
                }

                var module = ModuleDefinition.FromFile(targetAssemblyPath);
                var referenceImporter = new ReferenceImporter(module);

                // Import constructors for string handling (because we love strings!)
                var stringSByteCtor = referenceImporter.ImportMethod(typeof(string).GetConstructor(new[] { typeof(sbyte*) })!);
                var stringCharCtor = referenceImporter.ImportMethod(typeof(string).GetConstructor(new[] { typeof(char*) })!);
                var stringSByteWithLengthCtor = referenceImporter.ImportMethod(typeof(string).GetConstructor(new[] { typeof(sbyte*), typeof(int), typeof(int) })!);
                var stringCharWithLengthCtor = referenceImporter.ImportMethod(typeof(string).GetConstructor(new[] { typeof(char*), typeof(int), typeof(int) })!);

                Logger.Information("Obfuscation process starting...");

                // Set module attributes to ensure proper execution (because we need to be fancy!)
                module.Attributes &= ~DotNetDirectoryFlags.ILOnly;
                var is32Bit = module.MachineType == MachineType.I386;
                module.PEKind = is32Bit ? OptionalHeaderMagic.PE32 : OptionalHeaderMagic.PE32Plus;
                module.MachineType = is32Bit ? MachineType.I386 : MachineType.Amd64;
                if (is32Bit) module.Attributes |= DotNetDirectoryFlags.Bit32Required;

                var encodedStringsMap = new Dictionary<string, MethodDefinition>();

                // Loop through all types and their methods to find strings to obfuscate
                foreach (var type in module.GetAllTypes())
                {
                    foreach (var method in type.Methods)
                    {
                        var instructions = method.CilMethodBody!.Instructions;
                        for (var index = 0; index < instructions.Count; ++index)
                        {
                            var instruction = instructions[index];

                            // Look for string literals to obfuscate
                            if (instruction.OpCode == CilOpCodes.Ldstr && instruction.Operand is string { Length: > 0 } stringContent)
                            {
                                var encryptedContent = EncryptString(stringContent); // Encrypt the string (because who doesn't love encryption?)
                                var useUnicode = !IsAsciiCompatible(stringContent);
                                var requiresNullTerminator = !stringContent.Contains('\0');

                                // Check if we've already created a native method for this encrypted string
                                if (!encodedStringsMap.TryGetValue(encryptedContent, out var nativeMethod))
                                {
                                    nativeMethod = GenerateNativeMethodForString(encryptedContent, module, is32Bit, useUnicode, requiresNullTerminator);
                                    encodedStringsMap[encryptedContent] = nativeMethod; // Cache the method for future use
                                }

                                instruction.ReplaceWith(CilOpCodes.Call, nativeMethod); // Replace with a call to our native method

                                // Handle null terminators like a boss
                                if (requiresNullTerminator)
                                {
                                    instructions.Insert(++index, new CilInstruction(CilOpCodes.Newobj, useUnicode ? stringCharCtor : stringSByteCtor));
                                }
                                else
                                {
                                    instructions.InsertRange(++index, new[]
                                    {
                                        CilInstruction.CreateLdcI4(0), // Load 0 for the null terminator
                                        CilInstruction.CreateLdcI4(stringContent.Length), // Load the length of the string
                                        new CilInstruction(CilOpCodes.Newobj, useUnicode ? stringCharWithLengthCtor : stringSByteWithLengthCtor)
                                    });
                                    index += 2; // Adjusting index after inserting instructions
                                }
                            }
                        }
                    }
                }

                module.Write($"{targetAssemblyPath}_obfuscated.dll"); // Save the obfuscated assembly
                Logger.Success("Obfuscation completed successfully! Now it's even more secure!");
            }
            catch (Exception ex)
            {
                Logger.Error($"An error occurred: {ex.Message} (Oops! Did I do that?)");
            }
            finally
            {
                // Introduce a delay before closing the console (because good things come to those who wait!)
                Thread.Sleep(3000); // Wait for 3 seconds
            }
        }

        private static string EncryptString(string plainText)
        {
            // Check for null or empty strings (we don't want to encrypt nothing!)
            if (string.IsNullOrEmpty(plainText))
            {
                throw new ArgumentException("Plain text cannot be null or empty.", nameof(plainText));
            }

            using (var aes = Aes.Create())
            {
                aes.Key = Key; // Ensure this is 32 bytes for AES-256
                aes.GenerateIV(); // Generate a new IV for each encryption (because randomness is key!)

                using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                using var ms = new MemoryStream();
                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    using var writer = new StreamWriter(cs);
                    writer.Write(plainText); // Write the plain text into the stream (magic happens here!)
                }

                // Store the IV with the ciphertext for decryption (because we need to remember how we did it!)
                return Convert.ToBase64String(aes.IV) + ":" + Convert.ToBase64String(ms.ToArray());
            }
        }

        private static byte[] GenerateSecureKey()
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                var key = new byte[32]; // 256-bit key (the more, the merrier!)
                rng.GetBytes(key); // Fill the key with random bytes
                return key;
            }
        }

        private static MethodDefinition? GenerateNativeMethodForString(string stringContent, ModuleDefinition originalModule, bool isX86, bool useUnicode, bool addNullTerminator)
        {
            ArgumentNullException.ThrowIfNull(originalModule);
            ArgumentNullException.ThrowIfNull(stringContent);
            var factory = originalModule.CorLibTypeFactory;
            var obfuscatedMethodName = Guid.NewGuid().ToString("N"); // Generate a unique method name (because we like to keep things interesting!)

            // Create a new method definition for the obfuscated string
            var method = new MethodDefinition(obfuscatedMethodName, MethodAttributes.Public | MethodAttributes.Static, MethodSignature.CreateStatic(factory.SByte.MakePointerType()));
            method.ImplAttributes |= MethodImplAttributes.Native | MethodImplAttributes.Unmanaged | MethodImplAttributes.PreserveSig;
            method.Attributes |= MethodAttributes.PInvokeImpl;
            originalModule.GetOrCreateModuleType().Methods.Add(method);

            // Handle null terminator if needed (because we care about string integrity!)
            if (addNullTerminator)
            {
                stringContent += "\0"; // Handle null terminator
            }

            // Convert the string to bytes based on encoding type
            var stringBytes = useUnicode ? Encoding.Unicode.GetBytes(stringContent) : Encoding.ASCII.GetBytes(stringContent);
            var prefixInstructions = isX86 ? new byte[]
            {
                0x55, 0x89, 0xE5, 0xE8, 0x05, 0x00, 0x00, 0x00,
                0x83, 0xC0, 0x01, 0x5D, 0xC3, 0x58, 0x83, 0xC0, 0x0B, 0xEB, 0xF8
            } : new byte[]
            {
                0x48, 0x8D, 0x05, 0x01, 0x00, 0x00, 0x00, 0xC3
            };

            // Create the method body with the correct instructions
            Span<byte> methodBody = new byte[prefixInstructions.Length + stringBytes.Length];
            prefixInstructions.CopyTo(methodBody);
            stringBytes.CopyTo(methodBody[prefixInstructions.Length..]);

            var nativeBody = new NativeMethodBody(method) { Code = methodBody.ToArray() };
            Logger.Success($"Native method created: {obfuscatedMethodName} for string: {stringContent.TrimEnd()}");
            method.NativeMethodBody = nativeBody;
            return method; // Return the created method (because sharing is caring!)
        }

        private static bool IsAsciiCompatible(ReadOnlySpan<char> text)
        {
            foreach (var character in text)
            {
                if (character > '\x7F') return false; // Non-ASCII character found, return false
            }
            return true; // All characters are ASCII, return true
        }

        private static void ControlFlowObfuscation(MethodDefinition method)
        {
            var instructions = method.CilMethodBody!.Instructions;
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] randomBytes = new byte[4];
                rng.GetBytes(randomBytes);
                int fakeBranchIndex = BitConverter.ToInt32(randomBytes, 0) % instructions.Count; // Generate a fake branch index (because why not?)
                instructions.Insert(fakeBranchIndex, new CilInstruction(CilOpCodes.Nop)); // Insert a no-op instruction
                instructions.Insert(fakeBranchIndex + 1, new CilInstruction(CilOpCodes.Br, instructions[fakeBranchIndex + 2])); // Create a fake branch
            }
        }
    }
}