package com.upm.eui.tfc.scp.utiles;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.text.DateFormat;
import java.text.MessageFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERBoolean;
import org.bouncycastle.asn1.DEREnumerated;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERInputStream;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.X509Name;

/**
 * Clase que encapsula distintos metodos y procedimientos utiles para el manejo
 * de extensiones de certificados digitales (X509).
 * 
 * @version 1.0
 */

public class X509Ext extends Object {

	private String m_sName;

	private String m_sOid;

	private byte[] m_bValue;

	private boolean m_bCritical;
	private static final String AUTHORITY_KEY_IDENTIFIER_OLD_OID = "2.5.29.1";

	private static final String PRIMARY_KEY_ATTRIBUTES_OID = "2.5.29.2";

	private static final String CERTIFICATE_POLICIES_OLD_OID = "2.5.29.3";

	private static final String PRIMARY_KEY_USAGE_RESTRICTION_OID = "2.5.29.4";

	private static final String SUBJECT_DIRECTORY_ATTRIBUTES_OID = "2.5.29.9";

	private static final String BASIC_CONSTRAINTS_OLD_0_OID = "2.5.29.10";

	private static final String BASIC_CONSTRAINTS_OLD_1_OID = "2.5.29.13";

	private static final String SUBJECT_KEY_IDENTIFIER_OID = "2.5.29.14";

	private static final String KEY_USAGE_OID = "2.5.29.15";

	private static final String PRIVATE_KEY_USAGE_PERIOD_OID = "2.5.29.16";

	private static final String SUBJECT_ALTERNATIVE_NAME_OID = "2.5.29.17";

	private static final String ISSUER_ALTERNATIVE_NAME_OID = "2.5.29.18";

	private static final String BASIC_CONSTRAINTS_OID = "2.5.29.19";

	private static final String CRL_NUMBER_OID = "2.5.29.20";

	private static final String REASON_CODE_OID = "2.5.29.21";

	private static final String HOLD_INSTRUCTION_CODE_OID = "2.5.29.23";

	private static final String INVALIDITY_DATE_OID = "2.5.29.24";

	private static final String CRL_DISTRIBUTION_POINTS_OLD_OID = "2.5.29.25";

	private static final String DELTA_CRL_INDICATOR_OID = "2.5.29.27";

	private static final String ISSUING_DISTRIBUTION_POINT_OID = "2.5.29.28";

	private static final String CERTIFICATE_ISSUER_OID = "2.5.29.29";

	private static final String NAME_CONSTRAINTS_OID = "2.5.29.30";

	private static final String CRL_DISTRIBUTION_POINTS_OID = "2.5.29.31";

	private static final String CERTIFICATE_POLICIES_OID = "2.5.29.32";

	private static final String POLICY_MAPPINGS_OID = "2.5.29.33";

	private static final String POLICY_CONSTRAINTS_OLD_OID = "2.5.29.34";

	private static final String AUTHORITY_KEY_IDENTIFIER_OID = "2.5.29.35";

	private static final String POLICY_CONSTRAINTS_OID = "2.5.29.36";

	private static final String EXTENDED_KEY_USAGE_OID = "2.5.29.37";

	private static final String CRL_STREAM_IDENTIFIER_OID = "2.5.29.40";

	private static final String CRL_SCOPE_OID = "2.5.29.44";

	private static final String STATUS_REFERRALS_OID = "2.5.29.45";

	private static final String FRESHEST_CRL_OID = "2.5.29.46";

	private static final String ORDERED_LIST_OID = "2.5.29.47";

	private static final String BASE_UPDATE_TIME_OID = "2.5.29.51";

	private static final String DELTA_INFORMATION_OID = "2.5.29.53";

	private static final String INHIBIT_ANY_POLICY_OID = "2.5.29.54";

	private static final String NETSCAPE_CERTIFICATE_TYPE_OID = "2.16.840.1.113730.1.1";

	private static final String NETSCAPE_BASE_URL_OID = "2.16.840.1.113730.1.2";

	private static final String NETSCAPE_REVOCATION_URL_OID = "2.16.840.1.113730.1.3";

	private static final String NETSCAPE_CA_REVOCATION_URL_OID = "2.16.840.1.113730.1.4";

	private static final String NETSCAPE_CERTIFICATE_RENEWAL_URL_OID = "2.16.840.1.113730.1.7";

	private static final String NETSCAPE_CA_POLICY_URL_OID = "2.16.840.1.113730.1.8";

	private static final String NETSCAPE_SSL_SERVER_NAME_OID = "2.16.840.1.113730.1.12";

	private static final String NETSCAPE_COMMENT_OID = "2.16.840.1.113730.1.13";

	private static final int UNSPECIFIED_REASONCODE = 0;

	private static final int KEY_COMPROMISE_REASONCODE = 1;

	private static final int CA_COMPROMISE_REASONCODE = 2;

	private static final int AFFILIATION_CHANGED_REASONCODE = 3;

	private static final int SUPERSEDED_REASONCODE = 4;

	private static final int CESSATION_OF_OPERATION_REASONCODE = 5;

	private static final int CERTIFICATE_HOLD_REASONCODE = 6;

	private static final int REMOVE_FROM_CRL_REASONCODE = 8;

	private static final int PRIVILEGE_WITHDRAWN_REASONCODE = 9;

	private static final int AA_COMPROMISE_REASONCODE = 10;

	private static final String HOLD_INSTRUCTION_CODE_NONE_OID = "1.2.840.10040.2.1";

	private static final String HOLD_INSTRUCTION_CODE_CALL_ISSUER_OID = "1.2.840.10040.2.2";

	private static final String HOLD_INSTRUCTION_CODE_REJECT_OID = "1.2.840.10040.2.3";

	private static final String SERVERAUTH_EXT_KEY_USAGE_OID = "1.3.6.1.5.5.7.3.1";

	private static final String CLIENTAUTH_EXT_KEY_USAGE_OID = "1.3.6.1.5.5.7.3.2";

	private static final String CODESIGNING_EXT_KEY_USAGE_OID = "1.3.6.1.5.5.7.3.3";

	private static final String EMAILPROTECTION_EXT_KEY_USAGE_OID = "1.3.6.1.5.5.7.3.4";

	private static final String IPSECENDSYSTEM_EXT_KEY_USAGE_OID = "1.3.6.1.5.5.7.3.5";

	private static final String IPSECENDTUNNEL_EXT_KEY_USAGE_OID = "1.3.6.1.5.5.7.3.6";

	private static final String IPSECUSER_EXT_KEY_USAGE_OID = "1.3.6.1.5.5.7.3.7";

	private static final String TIMESTAMPING_EXT_KEY_USAGE_OID = "1.3.6.1.5.5.7.3.8";

	private static final String OCSPSIGNING_EXT_KEY_USAGE_OID = "1.3.6.1.5.5.7.3.9";

	public X509Ext(String sOid, byte[] bValue, boolean bCritical) {
		m_sOid = sOid;

		m_bValue = new byte[bValue.length];
		System.arraycopy(bValue, 0, m_bValue, 0, bValue.length);

		m_bCritical = bCritical;

		m_sName = lookupName();
	}

	private String lookupName() {

		if (m_sOid.equals(AUTHORITY_KEY_IDENTIFIER_OID)) {
			return "AuthorityKeyIdentifierCertExtString";
		} else if (m_sOid.equals(AUTHORITY_KEY_IDENTIFIER_OLD_OID)) {
			return "AuthorityKeyIdentifierOldCertExtString";
		} else if (m_sOid.equals(BASE_UPDATE_TIME_OID)) {
			return "BaseUpdateTimeCertExtString";
		} else if (m_sOid.equals(BASIC_CONSTRAINTS_OID)) {
			return "BasicConstraintsCertExtString";
		} else if (m_sOid.equals(BASIC_CONSTRAINTS_OLD_0_OID)) {
			return "BasicConstraintsOld0CertExtString";
		} else if (m_sOid.equals(BASIC_CONSTRAINTS_OLD_1_OID)) {
			return "BasicConstraintsOld1CertExtString";
		} else if (m_sOid.equals(CERTIFICATE_ISSUER_OID)) {
			return "CertificateIssuerCertExtString";
		} else if (m_sOid.equals(CERTIFICATE_POLICIES_OID)) {
			return "CertificatePoliciesCertExtString";
		} else if (m_sOid.equals(CERTIFICATE_POLICIES_OLD_OID)) {
			return "CertificatePoliciesOldCertExtString";
		} else if (m_sOid.equals(CRL_DISTRIBUTION_POINTS_OID)) {
			return "CrlDistributionPointsCertExtString";
		} else if (m_sOid.equals(CRL_DISTRIBUTION_POINTS_OLD_OID)) {
			return "CrlDistributionPointsOldCertExtString";
		} else if (m_sOid.equals(CRL_NUMBER_OID)) {
			return "CrlNumberCertExtString";
		} else if (m_sOid.equals(CRL_SCOPE_OID)) {
			return "CrlScopeCertExtString";
		} else if (m_sOid.equals(CRL_STREAM_IDENTIFIER_OID)) {
			return "CrlStreamIdentifierCertExtString";
		} else if (m_sOid.equals(DELTA_CRL_INDICATOR_OID)) {
			return "DeltaCrlIndicatorCertExtString";
		} else if (m_sOid.equals(DELTA_INFORMATION_OID)) {
			return "DeltaInformationCertExtString";
		} else if (m_sOid.equals(EXTENDED_KEY_USAGE_OID)) {
			return "ExtendedKeyUsageCertExtString";
		} else if (m_sOid.equals(FRESHEST_CRL_OID)) {
			return "FreshestCrlCertExtString";
		} else if (m_sOid.equals(HOLD_INSTRUCTION_CODE_OID)) {
			return "HoldInstructionCodeCertExtString";
		} else if (m_sOid.equals(INHIBIT_ANY_POLICY_OID)) {
			return "InhibitAnyPolicyCertExtString";
		} else if (m_sOid.equals(INVALIDITY_DATE_OID)) {
			return "InvalidityDateCertExtString";
		} else if (m_sOid.equals(ISSUER_ALTERNATIVE_NAME_OID)) {
			return "IssuerAlternativeNameCertExtString";
		} else if (m_sOid.equals(ISSUING_DISTRIBUTION_POINT_OID)) {
			return "IssuingDistributionPointCertExtString";
		} else if (m_sOid.equals(KEY_USAGE_OID)) {
			return "KeyUsageCertExtString";
		} else if (m_sOid.equals(NAME_CONSTRAINTS_OID)) {
			return "NameConstraintsCertExtString";
		} else if (m_sOid.equals(ORDERED_LIST_OID)) {
			return "OrderedListCertExtString";
		} else if (m_sOid.equals(POLICY_CONSTRAINTS_OID)) {
			return "PolicyConstraintsCertExtString";
		} else if (m_sOid.equals(POLICY_CONSTRAINTS_OLD_OID)) {
			return "PolicyConstraintsOldCertExtString";
		} else if (m_sOid.equals(POLICY_MAPPINGS_OID)) {
			return "PolicyMappingsCertExtString";
		} else if (m_sOid.equals(PRIMARY_KEY_ATTRIBUTES_OID)) {
			return "PrimaryKeyAttributesCertExtString";
		} else if (m_sOid.equals(PRIMARY_KEY_USAGE_RESTRICTION_OID)) {
			return "PrimaryKeyUsageRestrictionCertExtString";
		} else if (m_sOid.equals(PRIVATE_KEY_USAGE_PERIOD_OID)) {
			return "PrivateKeyUsagePeriodCertExtString";
		} else if (m_sOid.equals(REASON_CODE_OID)) {
			return "ReasonCodeCertExtString";
		} else if (m_sOid.equals(STATUS_REFERRALS_OID)) {
			return "StatusReferralsCertExtString";
		} else if (m_sOid.equals(SUBJECT_ALTERNATIVE_NAME_OID)) {
			return "SubjectAlternativeNameCertExtString";
		} else if (m_sOid.equals(SUBJECT_DIRECTORY_ATTRIBUTES_OID)) {
			return "SubjectDirectoryAttributesCertExtString";
		} else if (m_sOid.equals(SUBJECT_KEY_IDENTIFIER_OID)) {
			return "SubjectKeyIdentifierCertExtString";
		} else if (m_sOid.equals(NETSCAPE_CERTIFICATE_TYPE_OID)) {
			return "NetscapeCertificateTypeExtString";
		} else if (m_sOid.equals(NETSCAPE_BASE_URL_OID)) {
			return "NetscapeBaseUrlExtString";
		} else if (m_sOid.equals(NETSCAPE_REVOCATION_URL_OID)) {
			return "NetscapeRevocationUrlExtString";
		} else if (m_sOid.equals(NETSCAPE_CA_REVOCATION_URL_OID)) {
			return "NetscapeCaRevocationUrlExtString";
		} else if (m_sOid.equals(NETSCAPE_CERTIFICATE_RENEWAL_URL_OID)) {
			return "NetscapeCertificateRenewalUrlExtString";
		} else if (m_sOid.equals(NETSCAPE_CA_POLICY_URL_OID)) {
			return "NetscapeCaPolicyUrlExtString";
		} else if (m_sOid.equals(NETSCAPE_SSL_SERVER_NAME_OID)) {
			return "NetscapeSslServerNameExtString";
		} else if (m_sOid.equals(NETSCAPE_COMMENT_OID)) {
			return "NetscapeCommentExtString";
		} else {

			return null;
		}
	}

	public String getOid() {
		return m_sOid;
	}

	public byte[] getValue() {
		byte[] bValue = new byte[m_bValue.length];
		System.arraycopy(m_bValue, 0, bValue, 0, m_bValue.length);
		return bValue;
	}

	public boolean isCriticalExtension() {
		return m_bCritical;
	}

	public String getName() {
		if (m_sName == null) {
			return null;
		} else {
			return new String(m_sName);
		}
	}

	public String getStringValue() throws IOException, ParseException {
		ASN1InputStream ais = null;
		byte[] bOctets = null;

		try {
			ais = new ASN1InputStream(new ByteArrayInputStream(m_bValue));

			DEROctetString derOctStr = (DEROctetString) ais.readObject();

			bOctets = derOctStr.getOctets();
		} finally {
			try {
				if (ais != null)
					ais.close();
			} catch (IOException ex) { /* Ignorar */
			}
		}

		if (m_sOid.equals(SUBJECT_KEY_IDENTIFIER_OID)) {
			return getSubjectKeyIndentifierStringValue(bOctets);
		} else if (m_sOid.equals(KEY_USAGE_OID)) {
			return getKeyUsageStringValue(bOctets);
		} else if (m_sOid.equals(PRIVATE_KEY_USAGE_PERIOD_OID)) {
			return getPrivateKeyUsagePeriod(bOctets);
		} else if (m_sOid.equals(SUBJECT_ALTERNATIVE_NAME_OID)) {
			return getSubjectAlternativeName(bOctets);
		} else if (m_sOid.equals(ISSUER_ALTERNATIVE_NAME_OID)) {
			return getIssuerAlternativeName(bOctets);
		} else if (m_sOid.equals(BASIC_CONSTRAINTS_OID)) {
			return getBasicConstraintsStringValue(bOctets);
		} else if (m_sOid.equals(CRL_NUMBER_OID)) {
			return getCrlNumberStringValue(bOctets);
		} else if (m_sOid.equals(REASON_CODE_OID)) {
			return getReasonCodeStringValue(bOctets);
		} else if (m_sOid.equals(HOLD_INSTRUCTION_CODE_OID)) {
			return getHoldInstructionCodeStringValue(bOctets);
		} else if (m_sOid.equals(INVALIDITY_DATE_OID)) {
			return getInvalidityDateStringValue(bOctets);
		} else if (m_sOid.equals(DELTA_CRL_INDICATOR_OID)) {
			return getDeltaCrlIndicatorStringValue(bOctets);
		} else if (m_sOid.equals(CERTIFICATE_ISSUER_OID)) {
			return getCertificateIssuerStringValue(bOctets);
		} else if (m_sOid.equals(POLICY_MAPPINGS_OID)) {
			return getPolicyMappingsStringValue(bOctets);
		} else if (m_sOid.equals(AUTHORITY_KEY_IDENTIFIER_OID)) {
			return getAuthorityKeyIdentifierStringValue(bOctets);
		}

		else if (m_sOid.equals(POLICY_CONSTRAINTS_OID)) {
			return getPolicyConstraintsStringValue(bOctets);
		}

		else if (m_sOid.equals(EXTENDED_KEY_USAGE_OID)) {
			return getExtendedKeyUsageStringValue(bOctets);
		} else if (m_sOid.equals(INHIBIT_ANY_POLICY_OID)) {
			return getInhibitAnyPolicyStringValue(bOctets);
		} else if (m_sOid.equals(NETSCAPE_CERTIFICATE_TYPE_OID)) {
			return getNetscapeCertificateTypeStringValue(bOctets);
		}

		else if ((m_sOid.equals(NETSCAPE_BASE_URL_OID))
				|| (m_sOid.equals(NETSCAPE_REVOCATION_URL_OID))
				|| (m_sOid.equals(NETSCAPE_CA_REVOCATION_URL_OID))
				|| (m_sOid.equals(NETSCAPE_CERTIFICATE_RENEWAL_URL_OID))
				|| (m_sOid.equals(NETSCAPE_CA_POLICY_URL_OID))
				|| (m_sOid.equals(NETSCAPE_SSL_SERVER_NAME_OID))
				|| (m_sOid.equals(NETSCAPE_COMMENT_OID))) {
			return getNonNetscapeCertificateTypeStringValue(bOctets);
		}

		else {
			ByteArrayInputStream bais = null;

			try {

				StringBuffer strBuff = new StringBuffer();

				bais = new ByteArrayInputStream(bOctets);
				byte[] bLine = new byte[8];
				int iRead = -1;

				while ((iRead = bais.read(bLine)) != -1) {
					strBuff.append(getHexClearDump(bLine, iRead));
				}

				return strBuff.toString();
			} finally {
				try {
					if (bais != null)
						bais.close();
				} catch (IOException ex) { /* Ignore */
				}
			}
		}
	}

	private String getSubjectKeyIndentifierStringValue(byte[] bValue)
			throws IOException {

		DERInputStream dis = null;

		try {
			dis = new DERInputStream(new ByteArrayInputStream(bValue));
			DEROctetString derOctetStr = (DEROctetString) dis.readObject();

			byte[] bKeyIdent = derOctetStr.getOctets();

			StringBuffer strBuff = new StringBuffer();
			strBuff.append(convertToHexString(bKeyIdent));
			strBuff.append('\n');
			return strBuff.toString();
		} finally {
			try {
				if (dis != null)
					dis.close();
			} catch (IOException ex) { /* Ignorar */
			}
		}
	}

	private String getKeyUsageStringValue(byte[] bValue) throws IOException {

		DERInputStream dis = null;

		try {
			dis = new DERInputStream(new ByteArrayInputStream(bValue));
			DERBitString derBitStr = (DERBitString) dis.readObject();

			StringBuffer strBuff = new StringBuffer();

			byte[] bytes = derBitStr.getBytes();

			boolean bKeyAgreement = false;

			for (int iCnt = 0; iCnt < bytes.length; iCnt++) {
				boolean[] b = new boolean[8];

				b[7] = ((bytes[iCnt] & 0x80) == 0x80);
				b[6] = ((bytes[iCnt] & 0x40) == 0x40);
				b[5] = ((bytes[iCnt] & 0x20) == 0x20);
				b[4] = ((bytes[iCnt] & 0x10) == 0x10);
				b[3] = ((bytes[iCnt] & 0x8) == 0x8);
				b[2] = ((bytes[iCnt] & 0x4) == 0x4);
				b[1] = ((bytes[iCnt] & 0x2) == 0x2);
				b[0] = ((bytes[iCnt] & 0x1) == 0x1);

				if (iCnt == 0) {
					if (b[7] == true) {
						strBuff.append("DigitalSignatureKeyUsageString");
						strBuff.append('\n');
					}

					if (b[6] == true) {
						strBuff.append("NonRepudiationKeyUsageString");
						strBuff.append('\n');
					}

					if (b[5] == true) {
						strBuff.append("KeyEnciphermentKeyUsageString");
						strBuff.append('\n');
					}

					if (b[4] == true) {
						strBuff.append("DataEnciphermentKeyUsageString");
						strBuff.append('\n');
					}

					if (b[3] == true) {
						strBuff.append("KeyAgreementKeyUsageString");
						strBuff.append('\n');
						bKeyAgreement = true;
					}

					if (b[2] == true) {
						strBuff.append("KeyCertSignKeyUsageString");
						strBuff.append('\n');
					}

					if (b[1] == true) {
						strBuff.append("CrlSignKeyUsageString");
						strBuff.append('\n');
					}

					if ((b[0] == true) && bKeyAgreement) {
						strBuff.append("EncipherOnlyKeyUsageString");
						strBuff.append('\n');
					}
				}

				else if (iCnt == 1) {
					if ((b[7] == true) && bKeyAgreement) {
						strBuff.append("DecipherOnlyKeyUsageString");
						strBuff.append('\n');
					}
				}
			}

			return strBuff.toString();
		} finally {
			try {
				if (dis != null)
					dis.close();
			} catch (IOException ex) { /* Ignorar */
			}
		}
	}

	private String getPrivateKeyUsagePeriod(byte[] bValue) throws IOException,
			ParseException {

		DERInputStream dis = null;

		try {

			dis = new DERInputStream(new ByteArrayInputStream(bValue));
			ASN1Sequence times = (ASN1Sequence) dis.readObject();

			StringBuffer strBuff = new StringBuffer();

			for (Enumeration enumTimes = times.getObjects(); enumTimes
					.hasMoreElements();) {
				DERTaggedObject derTag = (DERTaggedObject) enumTimes
						.nextElement();

				if (derTag.getTagNo() == 0) {
					DEROctetString notBefore = (DEROctetString) derTag
							.getObject();
					DERGeneralizedTime notBeforeTime = new DERGeneralizedTime(
							new String(notBefore.getOctets()));
					strBuff
							.append(MessageFormat
									.format(
											"NotBeforePrivateKeyUsagePeriod",
											new String[] { formatGeneralizedTime(notBeforeTime) }));
					strBuff.append('\n');
				} else if (derTag.getTagNo() == 1) {
					DEROctetString notAfter = (DEROctetString) derTag
							.getObject();
					DERGeneralizedTime notAfterTime = new DERGeneralizedTime(
							new String(notAfter.getOctets()));
					strBuff
							.append(MessageFormat
									.format(
											"NotAfterPrivateKeyUsagePeriod",
											new String[] { formatGeneralizedTime(notAfterTime) }));
					strBuff.append('\n');
				}
			}

			return strBuff.toString();
		} finally {
			try {
				if (dis != null)
					dis.close();
			} catch (IOException ex) { /* Ignorar */
			}
		}
	}

	private String getSubjectAlternativeName(byte[] bValue) throws IOException {

		DERInputStream dis = null;

		try {
			dis = new DERInputStream(new ByteArrayInputStream(bValue));
			ASN1Sequence generalNames = (ASN1Sequence) dis.readObject();

			StringBuffer strBuff = new StringBuffer();

			for (Enumeration enumGN = generalNames.getObjects(); enumGN
					.hasMoreElements();) {
				DERTaggedObject generalName = (DERTaggedObject) enumGN
						.nextElement();

				strBuff.append(getGeneralNameString(generalName));
				strBuff.append('\n');
			}

			return strBuff.toString();
		} finally {
			try {
				if (dis != null)
					dis.close();
			} catch (IOException ex) { /* Ignore */
			}
		}
	}

	private String getIssuerAlternativeName(byte[] bValue) throws IOException {

		DERInputStream dis = null;

		try {
			StringBuffer strBuff = new StringBuffer();

			dis = new DERInputStream(new ByteArrayInputStream(bValue));
			ASN1Sequence generalNames = (ASN1Sequence) dis.readObject();

			for (Enumeration enumGN = generalNames.getObjects(); enumGN
					.hasMoreElements();) {
				DERTaggedObject generalName = (DERTaggedObject) enumGN
						.nextElement();
				strBuff.append(getGeneralNameString(generalName));
				strBuff.append('\n');
			}

			return strBuff.toString();
		} finally {
			try {
				if (dis != null)
					dis.close();
			} catch (IOException ex) { /* Ignorar */
			}
		}
	}

	private String getBasicConstraintsStringValue(byte[] bValue)
			throws IOException {

		DERInputStream dis = null;

		try {
			dis = new DERInputStream(new ByteArrayInputStream(bValue));
			ASN1Sequence asn1Seq = (ASN1Sequence) dis.readObject();

			boolean bCa = false;
			int iPathLengthConstraint = -1;

			if (asn1Seq.size() > 0) {
				DERBoolean derBool = (DERBoolean) asn1Seq.getObjectAt(0);
				bCa = derBool.isTrue();
			}

			if (asn1Seq.size() > 1) {
				DERInteger derInt = (DERInteger) asn1Seq.getObjectAt(1);
				iPathLengthConstraint = derInt.getValue().intValue();
			}

			StringBuffer strBuff = new StringBuffer();

			if (bCa) {
				strBuff.append("SubjectIsCa");
			} else {
				strBuff.append("SubjectIsNotCa");
			}
			strBuff.append('\n');

			if ((iPathLengthConstraint != -1) && (bCa)) {
				strBuff.append(MessageFormat.format("PathLengthConstraint",
						new String[] { "" + iPathLengthConstraint }));
			} else {
				strBuff.append("NoPathLengthConstraint");
			}
			strBuff.append('\n');

			return strBuff.toString();
		} finally {
			try {
				if (dis != null)
					dis.close();
			} catch (IOException ex) { /* Ignore */
			}
		}
	}

	private String getCrlNumberStringValue(byte[] bValue) throws IOException {

		DERInputStream dis = null;

		try {
			dis = new DERInputStream(new ByteArrayInputStream(bValue));
			DERInteger derInt = (DERInteger) dis.readObject();

			StringBuffer strBuff = new StringBuffer();

			strBuff.append(convertToHexString(derInt));
			strBuff.append('\n');
			return strBuff.toString();
		} finally {
			try {
				if (dis != null)
					dis.close();
			} catch (IOException ex) { /* Ignore */
			}
		}
	}

	private String getReasonCodeStringValue(byte[] bValue) throws IOException {

		DERInputStream dis = null;

		try {

			dis = new DERInputStream(new ByteArrayInputStream(bValue));

			DEREnumerated derEnum = (DEREnumerated) dis.readObject();

			BigInteger reasonCode = derEnum.getValue();

			int iReasonCode = reasonCode.intValue();
			String sReasonCodeString = null;

			if (iReasonCode == UNSPECIFIED_REASONCODE) {
				sReasonCodeString = "UnspecifiedReasonCodeString";
			} else if (iReasonCode == KEY_COMPROMISE_REASONCODE) {
				sReasonCodeString = "KeyCompromiseReasonCodeString";
			} else if (iReasonCode == CA_COMPROMISE_REASONCODE) {
				sReasonCodeString = "CaCompromiseReasonCodeString";
			} else if (iReasonCode == AFFILIATION_CHANGED_REASONCODE) {
				sReasonCodeString = "AffiliationChangedReasonCodeString";
			} else if (iReasonCode == SUPERSEDED_REASONCODE) {
				sReasonCodeString = "SupersededReasonCodeString";
			} else if (iReasonCode == CESSATION_OF_OPERATION_REASONCODE) {
				sReasonCodeString = "CessationOfOperationReasonCodeString";
			} else if (iReasonCode == CERTIFICATE_HOLD_REASONCODE) {
				sReasonCodeString = "CertificateHoldReasonCodeString";
			} else if (iReasonCode == REMOVE_FROM_CRL_REASONCODE) {
				sReasonCodeString = "RemoveFromCrlReasonCodeString";
			} else if (iReasonCode == PRIVILEGE_WITHDRAWN_REASONCODE) {
				sReasonCodeString = "PrivilegeWithdrawnReasonCodeString";
			} else if (iReasonCode == AA_COMPROMISE_REASONCODE) {
				sReasonCodeString = "AaCompromiseReasonCodeString";
			} else {
				sReasonCodeString = "UnrecognisedReasonCodeString";
			}

			StringBuffer strBuff = new StringBuffer();
			strBuff.append(MessageFormat.format(sReasonCodeString,
					new String[] { "" + iReasonCode }));
			strBuff.append('\n');
			return strBuff.toString();
		} finally {
			try {
				if (dis != null)
					dis.close();
			} catch (IOException ex) { /* Ignore */
			}
		}
	}

	private String getHoldInstructionCodeStringValue(byte[] bValue)
			throws IOException {

		DERInputStream dis = null;

		try {
			dis = new DERInputStream(new ByteArrayInputStream(bValue));
			DERObjectIdentifier holdInstructionCode = (DERObjectIdentifier) dis
					.readObject();
			String sHoldInstructionCode = holdInstructionCode.getId();

			StringBuffer strBuff = new StringBuffer();

			if (sHoldInstructionCode.equals(HOLD_INSTRUCTION_CODE_NONE_OID)) {
				strBuff.append(MessageFormat.format("HoldInstructionCodeNone",
						new String[] { sHoldInstructionCode }));
			} else if (sHoldInstructionCode
					.equals(HOLD_INSTRUCTION_CODE_CALL_ISSUER_OID)) {
				strBuff.append(MessageFormat.format(
						"HoldInstructionCodeCallIssuer",
						new String[] { sHoldInstructionCode }));
			} else if (sHoldInstructionCode
					.equals(HOLD_INSTRUCTION_CODE_REJECT_OID)) {
				strBuff.append(MessageFormat.format(
						"HoldInstructionCodeReject",
						new String[] { sHoldInstructionCode }));
			} else {
				strBuff.append(sHoldInstructionCode);
			}
			strBuff.append('\n');

			return strBuff.toString();
		} finally {
			try {
				if (dis != null)
					dis.close();
			} catch (IOException ex) { /* Ignore */
			}
		}
	}

	private String getInvalidityDateStringValue(byte[] bValue)
			throws IOException, ParseException {

		DERInputStream dis = null;

		try {
			dis = new DERInputStream(new ByteArrayInputStream(bValue));
			DERGeneralizedTime invalidityDate = (DERGeneralizedTime) dis
					.readObject();

			String sInvalidityTime = formatGeneralizedTime(invalidityDate);

			StringBuffer strBuff = new StringBuffer();
			strBuff.append(sInvalidityTime);
			strBuff.append('\n');
			return strBuff.toString();
		} finally {
			try {
				if (dis != null)
					dis.close();
			} catch (IOException ex) { /* Ignore */
			}
		}
	}

	private String getDeltaCrlIndicatorStringValue(byte[] bValue)
			throws IOException {

		DERInputStream dis = null;

		try {

			dis = new DERInputStream(new ByteArrayInputStream(bValue));
			DERInteger derInt = (DERInteger) dis.readObject();

			StringBuffer strBuff = new StringBuffer();
			strBuff.append(convertToHexString(derInt));
			strBuff.append('\n');
			return strBuff.toString();
		} finally {
			try {
				if (dis != null)
					dis.close();
			} catch (IOException ex) { /* Ignore */
			}
		}
	}

	private String getCertificateIssuerStringValue(byte[] bValue)
			throws IOException {

		DERInputStream dis = null;

		try {
			StringBuffer strBuff = new StringBuffer();

			dis = new DERInputStream(new ByteArrayInputStream(bValue));
			ASN1Sequence generalNames = (ASN1Sequence) dis.readObject();

			for (Enumeration enumGN = generalNames.getObjects(); enumGN
					.hasMoreElements();) {
				DERTaggedObject generalName = (DERTaggedObject) enumGN
						.nextElement();

				strBuff.append(getGeneralNameString(generalName));
				strBuff.append('\n');
			}

			return strBuff.toString();
		} finally {
			try {
				if (dis != null)
					dis.close();
			} catch (IOException ex) { /* Ignore */
			}
		}
	}

	private String getPolicyMappingsStringValue(byte[] bValue)
			throws IOException {

		DERInputStream dis = null;

		try {

			dis = new DERInputStream(new ByteArrayInputStream(bValue));
			ASN1Sequence policyMappings = (ASN1Sequence) dis.readObject();

			StringBuffer strBuff = new StringBuffer();

			int iCnt = 1;
			for (Enumeration enumPM = policyMappings.getObjects(); enumPM
					.hasMoreElements();) {
				ASN1Sequence policyMapping = (ASN1Sequence) enumPM
						.nextElement();

				strBuff.append(MessageFormat.format("PolicyMapping",
						new String[] { "" + iCnt }));
				strBuff.append('\n');

				if (policyMapping.size() > 0) {
					DERObjectIdentifier issuerDomainPolicy = (DERObjectIdentifier) policyMapping
							.getObjectAt(0);
					strBuff.append('\t');
					strBuff.append(MessageFormat.format("IssuerDomainPolicy",
							new String[] { issuerDomainPolicy.getId() }));
					strBuff.append('\n');
				}

				if (policyMapping.size() > 1) {
					DERObjectIdentifier subjectDomainPolicy = (DERObjectIdentifier) policyMapping
							.getObjectAt(1);
					strBuff.append('\t');
					strBuff.append(MessageFormat.format("SubjectDomainPolicy",
							new String[] { subjectDomainPolicy.getId() }));
					strBuff.append('\n');
				}

				iCnt++;
			}

			strBuff.append('\n');

			return strBuff.toString();
		} finally {
			try {
				if (dis != null)
					dis.close();
			} catch (IOException ex) { /* Ignore */
			}
		}
	}

	private String getAuthorityKeyIdentifierStringValue(byte[] bValue)
			throws IOException {

		DERInputStream dis = null;

		try {
			dis = new DERInputStream(new ByteArrayInputStream(bValue));

			ASN1Sequence asn1Seq = (ASN1Sequence) dis.readObject();

			DEROctetString keyIdentifier = null;
			ASN1Sequence authorityCertIssuer = null;
			DEROctetString certificateSerialNumber = null;

			for (int iCnt = 0; iCnt < asn1Seq.size(); iCnt++) {
				DERTaggedObject derTagObj = (DERTaggedObject) asn1Seq
						.getObjectAt(iCnt);

				int iTagNo = derTagObj.getTagNo();

				DERObject derObj = (DERObject) derTagObj.getObject();

				if (iTagNo == 0) {
					keyIdentifier = (DEROctetString) derObj;
				} else if (iTagNo == 1) {

					if (derObj instanceof ASN1Sequence) {
						authorityCertIssuer = (ASN1Sequence) derObj;
					}

					else {
						authorityCertIssuer = new DERSequence(derObj);
					}
				} else if (iTagNo == 2) {
					certificateSerialNumber = (DEROctetString) derObj;
				}
			}

			StringBuffer strBuff = new StringBuffer();

			if (keyIdentifier != null) {

				byte[] bKeyIdent = keyIdentifier.getOctets();

				strBuff.append(MessageFormat.format("KeyIdentifier",
						new String[] { convertToHexString(bKeyIdent) }));
				strBuff.append('\n');
			}

			if (authorityCertIssuer != null) {
				strBuff.append("CertificateIssuer");
				strBuff.append('\n');

				for (Enumeration enumACI = authorityCertIssuer.getObjects(); enumACI
						.hasMoreElements();) {
					DERTaggedObject generalName = (DERTaggedObject) enumACI
							.nextElement();
					strBuff.append('\t');
					strBuff.append(getGeneralNameString(generalName));
					strBuff.append('\n');
				}
			}

			if (certificateSerialNumber != null) {

				byte[] bCertSerialNumber = certificateSerialNumber.getOctets();

				strBuff
						.append(MessageFormat
								.format(
										"CertificateSerialNumber",
										new String[] { convertToHexString(bCertSerialNumber) }));
				strBuff.append('\n');
			}

			return strBuff.toString();
		} finally {
			try {
				if (dis != null)
					dis.close();
			} catch (IOException ex) { /* Ignore */
			}
		}
	}

	private String getPolicyConstraintsStringValue(byte[] bValue)
			throws IOException {

		DERInputStream dis = null;

		try {
			dis = new DERInputStream(new ByteArrayInputStream(bValue));
			ASN1Sequence policyConstraints = (ASN1Sequence) dis.readObject();

			StringBuffer strBuff = new StringBuffer();

			for (Enumeration enumPC = policyConstraints.getObjects(); enumPC
					.hasMoreElements();) {

				DERTaggedObject policyConstraint = (DERTaggedObject) enumPC
						.nextElement();
				DERInteger skipCerts = new DERInteger(
						((DEROctetString) policyConstraint.getObject())
								.getOctets());
				int iSkipCerts = skipCerts.getValue().intValue();

				if (policyConstraint.getTagNo() == 0) {
					strBuff.append(MessageFormat.format(
							"RequireExplicitPolicy", new String[] { ""
									+ iSkipCerts }));
					strBuff.append('\n');
				} else if (policyConstraint.getTagNo() == 1) {
					strBuff.append(MessageFormat.format("InhibitPolicyMapping",
							new String[] { "" + iSkipCerts }));
					strBuff.append('\n');
				}
			}

			return strBuff.toString();
		} finally {
			try {
				if (dis != null)
					dis.close();
			} catch (IOException ex) { /* Ignore */
			}
		}
	}

	private String getExtendedKeyUsageStringValue(byte[] bValue)
			throws IOException {

		DERInputStream dis = null;

		try {
			dis = new DERInputStream(new ByteArrayInputStream(bValue));
			ASN1Sequence asn1Seq = (ASN1Sequence) dis.readObject();

			StringBuffer strBuff = new StringBuffer();

			for (int iCnt = 0; iCnt < asn1Seq.size(); iCnt++) {
				DERObjectIdentifier derOid = (DERObjectIdentifier) asn1Seq
						.getObjectAt(iCnt);
				String sOid = derOid.getId();
				String sExtKeyUsage = null;

				if (sOid.equals(SERVERAUTH_EXT_KEY_USAGE_OID)) {
					sExtKeyUsage = "ServerAuthExtKeyUsageString";
				} else if (sOid.equals(CLIENTAUTH_EXT_KEY_USAGE_OID)) {
					sExtKeyUsage = "ClientAuthExtKeyUsageString";
				} else if (sOid.equals(CODESIGNING_EXT_KEY_USAGE_OID)) {
					sExtKeyUsage = "CodeSigningExtKeyUsageString";
				} else if (sOid.equals(EMAILPROTECTION_EXT_KEY_USAGE_OID)) {
					sExtKeyUsage = "EmailProtectionExtKeyUsageString";
				} else if (sOid.equals(IPSECENDSYSTEM_EXT_KEY_USAGE_OID)) {
					sExtKeyUsage = "IpsecEndSystemExtKeyUsageString";
				} else if (sOid.equals(IPSECENDTUNNEL_EXT_KEY_USAGE_OID)) {
					sExtKeyUsage = "IpsecTunnelExtKeyUsageString";
				} else if (sOid.equals(IPSECUSER_EXT_KEY_USAGE_OID)) {
					sExtKeyUsage = "IpsecUserExtKeyUsageString";
				} else if (sOid.equals(TIMESTAMPING_EXT_KEY_USAGE_OID)) {
					sExtKeyUsage = "TimeStampingExtKeyUsageString";
				} else if (sOid.equals(OCSPSIGNING_EXT_KEY_USAGE_OID)) {
					sExtKeyUsage = "OcspSigningExtKeyUsageString";
				} else {
					sExtKeyUsage = "UnrecognisedExtKeyUsageString";
				}

				strBuff.append(MessageFormat.format(sExtKeyUsage,
						new String[] { sOid }));
				strBuff.append('\n');
			}

			return strBuff.toString();
		} finally {
			try {
				if (dis != null)
					dis.close();
			} catch (IOException ex) { /* Ignorar */
			}
		}
	}

	private String getInhibitAnyPolicyStringValue(byte[] bValue)
			throws IOException {
		DERInputStream dis = null;

		try {

			dis = new DERInputStream(new ByteArrayInputStream(bValue));
			DERInteger skipCerts = (DERInteger) dis.readObject();

			int iSkipCerts = skipCerts.getValue().intValue();

			StringBuffer strBuff = new StringBuffer();
			strBuff.append(MessageFormat.format("InhibitAnyPolicy",
					new String[] { "" + iSkipCerts }));
			strBuff.append('\n');
			return strBuff.toString();
		} finally {
			try {
				if (dis != null)
					dis.close();
			} catch (IOException ex) { /* Ignorar */
			}
		}
	}

	private String getNetscapeCertificateTypeStringValue(byte[] bValue)
			throws IOException {
		DERInputStream dis = null;

		try {
			dis = new DERInputStream(new ByteArrayInputStream(bValue));
			DERBitString derBitStr = (DERBitString) dis.readObject();

			StringBuffer strBuff = new StringBuffer();

			byte[] bytes = derBitStr.getBytes();

			boolean bKeyAgreement = false;

			if (bytes.length > 0) {
				boolean[] b = new boolean[8];

				b[7] = ((bytes[0] & 0x80) == 0x80);
				b[6] = ((bytes[0] & 0x40) == 0x40);
				b[5] = ((bytes[0] & 0x20) == 0x20);
				b[4] = ((bytes[0] & 0x10) == 0x10);
				b[3] = ((bytes[0] & 0x8) == 0x8);
				b[2] = ((bytes[0] & 0x4) == 0x4);
				b[1] = ((bytes[0] & 0x2) == 0x2);
				b[0] = ((bytes[0] & 0x1) == 0x1);

				if (b[7] == true) {
					strBuff.append("SslClientNetscapeCertificateType");
					strBuff.append('\n');
				}

				if (b[6] == true) {
					strBuff.append("SslServerNetscapeCertificateType");
					strBuff.append('\n');
				}

				if (b[5] == true) {
					strBuff.append("SmimeNetscapeCertificateType");
					strBuff.append('\n');
				}

				if (b[4] == true) {
					strBuff.append("ObjectSigningNetscapeCertificateType");
					strBuff.append('\n');
					bKeyAgreement = true;
				}

				if (b[2] == true) {
					strBuff.append("SslCaNetscapeCertificateType");
					strBuff.append('\n');
				}

				if (b[1] == true) {
					strBuff.append("SmimeCaNetscapeCertificateType");
					strBuff.append('\n');
				}

				if (b[0] == true) {
					strBuff.append("ObjectSigningCaNetscapeCertificateType");
					strBuff.append('\n');
				}
			}

			return strBuff.toString();
		} finally {
			try {
				if (dis != null)
					dis.close();
			} catch (IOException ex) { /* Ignorar */
			}
		}
	}

	private String getNonNetscapeCertificateTypeStringValue(byte[] bValue)
			throws IOException {
		DERInputStream dis = null;

		try {
			dis = new DERInputStream(new ByteArrayInputStream(bValue));
			DERIA5String derStr = (DERIA5String) dis.readObject();

			StringBuffer strBuff = new StringBuffer();

			strBuff.append(derStr.getString());
			strBuff.append('\n');
			return strBuff.toString();
		} finally {
			try {
				if (dis != null)
					dis.close();
			} catch (IOException ex) { /* Ignorar */
			}
		}
	}

	private String getGeneralNameString(DERTaggedObject generalName) {

		StringBuffer strBuff = new StringBuffer();

		int iTagNo = generalName.getTagNo();

		if (iTagNo == 1) {
			DEROctetString rfc822 = (DEROctetString) generalName.getObject();
			String sRfc822 = new String(rfc822.getOctets());
			strBuff.append(MessageFormat.format("Rfc822GeneralName",
					new String[] { sRfc822 }));
		} else if (iTagNo == 2) {
			DEROctetString dns = (DEROctetString) generalName.getObject();
			String sDns = new String(dns.getOctets());
			strBuff.append(MessageFormat.format("DnsGeneralName",
					new String[] { sDns }));
		} else if (iTagNo == 4) {
			ASN1Sequence directory = (ASN1Sequence) generalName.getObject();
			X509Name name = new X509Name(directory);
			strBuff.append(MessageFormat.format("DirectoryGeneralName",
					new String[] { name.toString() }));
		} else if (iTagNo == 6) {
			DEROctetString uri = (DEROctetString) generalName.getObject();
			String sUri = new String(uri.getOctets());
			strBuff.append(MessageFormat.format("UriGeneralName",
					new String[] { sUri }));
		} else if (iTagNo == 7) {
			DEROctetString ipAddress = (DEROctetString) generalName.getObject();

			byte[] bIpAddress = ipAddress.getOctets();

			StringBuffer sbIpAddress = new StringBuffer();

			for (int iCnt = 0; iCnt < bIpAddress.length; iCnt++) {
				byte b = bIpAddress[iCnt];

				sbIpAddress.append((int) b & 0xFF);

				if ((iCnt + 1) < bIpAddress.length) {
					sbIpAddress.append('.');
				}
			}

			strBuff.append(MessageFormat.format("IpAddressGeneralName",
					new String[] { sbIpAddress.toString() }));
		} else if (iTagNo == 8) {
			DEROctetString registeredId = (DEROctetString) generalName
					.getObject();

			byte[] bRegisteredId = registeredId.getOctets();

			StringBuffer sbRegisteredId = new StringBuffer();

			for (int iCnt = 0; iCnt < bRegisteredId.length; iCnt++) {
				byte b = bRegisteredId[iCnt];

				sbRegisteredId.append((int) b & 0xFF);

				if ((iCnt + 1) < bRegisteredId.length) {
					sbRegisteredId.append('.');
				}
			}

			strBuff.append(MessageFormat.format("RegisteredIdGeneralName",
					new String[] { sbRegisteredId.toString() }));

		} else {
			strBuff.append(MessageFormat.format("UnsupportedGeneralNameType",
					new String[] { "" + iTagNo }));
		}
		return strBuff.toString();
	}

	private String formatGeneralizedTime(DERGeneralizedTime time)
			throws ParseException {

		String sTime = time.getTime();

		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmssz");

		Date date = dateFormat.parse(sTime);

		sTime = DateFormat.getDateTimeInstance(DateFormat.MEDIUM,
				DateFormat.LONG).format((Date) date);

		return sTime;
	}

	private String getHexClearDump(byte[] bytes, int iLen) {

		StringBuffer sbHex = new StringBuffer();

		StringBuffer sbClr = new StringBuffer();

		for (int iCnt = 0; iCnt < iLen; iCnt++) {

			byte b = bytes[iCnt];
			int i = (int) b & 0xFF;

			int i1 = (int) Math.floor(i / 16);

			int i2 = i % 16;

			sbHex.append(Character.toUpperCase(Character.forDigit(i1, 16)));
			sbHex.append(Character.toUpperCase(Character.forDigit(i2, 16)));

			if ((iCnt + 1) < iLen) {

				sbHex.append(' ');
			}

			char c = '.';

			if ((!Character.isISOControl((char) i))
					&& (Character.isDefined((char) i))) {
				Character cClr = new Character((char) i);
				c = cClr.charValue();
			}

			sbClr.append(c);
		}

		StringBuffer strBuff = new StringBuffer();

		strBuff.append(sbHex.toString());
		sbHex = new StringBuffer();

		int iMissing = bytes.length - iLen;
		for (int iCnt = 0; iCnt < iMissing; iCnt++) {
			strBuff.append("   ");
		}

		strBuff.append("   ");
		strBuff.append(sbClr.toString());
		sbClr = new StringBuffer();
		strBuff.append('\n');

		return strBuff.toString();
	}

	private String convertToHexString(DERInteger derInt) {

		String sHexCrlNumber = derInt.getValue().toString(16).toUpperCase();

		StringBuffer strBuff = new StringBuffer();

		for (int iCnt = 0; iCnt < sHexCrlNumber.length(); iCnt++) {
			strBuff.append(sHexCrlNumber.charAt(iCnt));

			if ((((iCnt + 1) % 4) == 0)
					&& ((iCnt + 1) != sHexCrlNumber.length())) {
				strBuff.append(' ');
			}
		}

		return strBuff.toString();
	}

	private String convertToHexString(byte[] bytes) {

		StringBuffer strBuff = new StringBuffer(new BigInteger(1, bytes)
				.toString(16).toUpperCase());

		if (strBuff.length() > 4) {
			for (int iCnt = 4; iCnt < strBuff.length(); iCnt += 5) {
				strBuff.insert(iCnt, ' ');
			}
		}

		return strBuff.toString();
	}
}
