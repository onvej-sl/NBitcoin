#if HAS_SPAN
#nullable enable
using NBitcoin.DataEncoders;
using NBitcoin.Secp256k1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NBitcoin
{
	public class TaprootAddress : BitcoinAddress, IBech32Data, IPubkeyHashUsable
	{
		public TaprootAddress(string bech32, Network expectedNetwork)
				: base(Validate(bech32, expectedNetwork), expectedNetwork)
		{
			if (expectedNetwork.GetBech32Encoder(Bech32Type.TAPROOT_ADDRESS, false) is Bech32Encoder encoder)
			{
				var decoded = encoder.Decode(bech32, out _);
				if (ECXOnlyPubKey.TryCreate(decoded, out var k))
					_PubKey = new PubKey(k);
				else
					throw new FormatException("Invalid TaprootAddress");
			}
			else
				throw expectedNetwork.Bech32NotSupported(Bech32Type.TAPROOT_ADDRESS);
		}
		internal TaprootAddress(string str, byte[] key, Network network) : base(str, network)
		{
			if (ECXOnlyPubKey.TryCreate(key, out var k))
				_PubKey = new PubKey(k);
			else
				throw new FormatException("Invalid TaprootAddress");
		}

		private static string Validate(string bech32, Network expectedNetwork)
		{
			if (bech32 == null)
				throw new ArgumentNullException(nameof(bech32));
			if (expectedNetwork == null)
				throw new ArgumentNullException(nameof(expectedNetwork));

			if (expectedNetwork.GetBech32Encoder(Bech32Type.TAPROOT_ADDRESS, false) is Bech32Encoder encoder)
			{
				try
				{
					byte witVersion;
					var data = encoder.Decode(bech32, out witVersion);
					if (data.Length == 32 && witVersion == 1)
					{
						return bech32;
					}
				}
				catch (Bech32FormatException) { throw; }
				catch (FormatException) { }
			}
			else
			{
				throw expectedNetwork.Bech32NotSupported(Bech32Type.TAPROOT_ADDRESS);
			}
			throw new FormatException("Invalid TaprootAddress");
		}

		public TaprootAddress(PubKey pubKey, Network network) :
			base(NotNull(pubKey) ?? Network.CreateBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, pubKey.ToBytes(), 0, network), network)
		{
			_PubKey = pubKey;
		}

		private static string? NotNull(PubKey pubKey)
		{
			if (pubKey == null)
				throw new ArgumentNullException(nameof(pubKey));
			return null;
		}

		public bool VerifyMessage(string message, string signature)
		{
			if (message == null)
				throw new ArgumentNullException(nameof(message));
			if (signature == null)
				throw new ArgumentNullException(nameof(signature));
			var key = NBitcoin.PubKey.RecoverFromMessage(message, signature);
			return key == PubKey;
		}

		public bool VerifyMessage(byte[] message, byte[] signature)
		{
			var key = NBitcoin.PubKey.RecoverFromMessage(message, signature);
			return key == PubKey;
		}

		PubKey _PubKey;
		public PubKey PubKey
		{
			get
			{
				return _PubKey;
			}
		}


		protected override Script GeneratePaymentScript()
		{
			return PayToWitTemplate.Instance.GenerateScriptPubKey(OpcodeType.OP_1, PubKey.ToBytes(true));
		}

		public Bech32Type Type
		{
			get
			{
				return Bech32Type.TAPROOT_ADDRESS;
			}
		}
	}
}
#nullable disable
#endif
