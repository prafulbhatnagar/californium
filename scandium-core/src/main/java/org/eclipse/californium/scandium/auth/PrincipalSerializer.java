package org.eclipse.californium.scandium.auth;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Principal;

import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.scandium.util.DatagramReader;
import org.eclipse.californium.scandium.util.DatagramWriter;

/**
 * A helper for serializing and deserializing principals supported by Scandium.
 */
public final class PrincipalSerializer {

	private PrincipalSerializer() {
	}

	/**
	 * Serializes a principal to a byte array.
	 * 
	 * @param principal The principal to serialize.
	 * @param writer The writer to serialize to.
	 * @throws NullPointerException if any of the params is {@code null}.
	 */
	public static void serialize(final Principal principal, final DatagramWriter writer) {
		if (principal == null) {
			throw new NullPointerException("Prinicpal must not be null");
		} else if (writer == null) {
			throw new NullPointerException("Writer must not be null");
		} else if (principal instanceof PreSharedKeyIdentity) {
			serialize(PrincipalType.TYPE_PSK_PRINCIPAL, principal, writer);
		} else if (principal instanceof RawPublicKeyIdentity) {
			serializeSubjectInfo((RawPublicKeyIdentity) principal, writer);
		} else if (principal instanceof X500Principal) {
			serialize( PrincipalType.TYPE_X500_PRINCIPAL, principal, writer);
		} else {
			serialize(PrincipalType.TYPE_GENERIC_PRINCIPAL, principal, writer);
		}
	}

	private static void serialize(final PrincipalType type, final Principal principal, final DatagramWriter writer) {
		writer.writeByte(type.code);
		writeBytes(principal.getName().getBytes(StandardCharsets.UTF_8), writer);
	}

	private static void serializeSubjectInfo(final RawPublicKeyIdentity principal, final DatagramWriter writer) {
		writer.writeByte(PrincipalType.TYPE_RPK_PRINCIPAL.code);
		writeBytes(principal.getSubjectInfo(), writer);
	}

	private static void writeBytes(final byte[] bytesToWrite, final DatagramWriter writer) {
		writer.write(bytesToWrite.length, 16);
		writer.writeBytes(bytesToWrite);
	}

	/**
	 * Deserializes a principal from its byte array representation.
	 * 
	 * @param reader The reader containing the byte array.
	 * @return The principal object or {@code null} if the reader does not contain a supported principal type.
	 * @throws GeneralSecurityException if the reader contains a raw public key principal that could not be recreated.
	 */
	public static Principal deserialize(DatagramReader reader) throws GeneralSecurityException {
		int code = reader.read(8);
		PrincipalType type = PrincipalType.fromCode((byte) code);
		switch(type) {
		case TYPE_GENERIC_PRINCIPAL:
			return deserializeGeneric(reader);
		case TYPE_X500_PRINCIPAL:
			return deserializeSubjectName(reader);
		case TYPE_PSK_PRINCIPAL:
			return deserializeKey(reader);
		case TYPE_RPK_PRINCIPAL:
			return deserializeSubjectInfo(reader);
		default:
			return null;
		}
	}

	private static X500Principal deserializeSubjectName(DatagramReader reader) {
		return new X500Principal(new String(readAll(reader)));
	};

	private static PreSharedKeyIdentity deserializeKey(DatagramReader reader) {
		return new PreSharedKeyIdentity(new String(readAll(reader)));
	};

	private static RawPublicKeyIdentity deserializeSubjectInfo(DatagramReader reader) throws GeneralSecurityException {
		byte[] subjectInfo = readAll(reader);
		return new RawPublicKeyIdentity(subjectInfo);
	}

	private static Principal deserializeGeneric(final DatagramReader reader) {
		final String name = new String(readAll(reader));
		return new Principal() {

			@Override
			public String getName() {
				return name;
			}
		};
	}

	private static byte[] readAll(DatagramReader reader) {
		int length = reader.read(16);
		return reader.readBytes(length);
	}

	private enum PrincipalType {

		TYPE_GENERIC_PRINCIPAL((byte) 0x00),
		TYPE_X500_PRINCIPAL((byte) 0x01),
		TYPE_PSK_PRINCIPAL((byte) 0x02),
		TYPE_RPK_PRINCIPAL((byte) 0x03);

		private byte code;

		private PrincipalType(final byte code) {
			this.code = code;
		}

		static PrincipalType fromCode(final byte code) {
			for (PrincipalType type : values()) {
				if (type.code == code) {
					return type;
				}
			}
			return null;
		}
	}
}
