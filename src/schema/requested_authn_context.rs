use crate::schema::AuthnContextClassRef;
use quick_xml::events::{BytesEnd, BytesStart, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

const NAME: &str = "saml2p:RequestedAuthnContext";
const SCHEMA: (&str, &str) = ("xmlns:saml2", "urn:oasis:names:tc:SAML:2.0:assertion");

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct RequestedAuthnContext {
    #[serde(rename = "AuthnContextClassRef")]
    pub authn_context_class_refs: Option<Vec<AuthnContextClassRef>>,
    #[serde(rename = "AuthnContextDeclRef")]
    pub authn_context_decl_refs: Option<Vec<AuthnContextDeclRef>>,
    #[serde(rename = "Comparison")]
    pub comparison: Option<AuthnContextComparison>,
}

impl RequestedAuthnContext {
    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::borrowed(NAME.as_bytes(), NAME.len());
        root.push_attribute(SCHEMA);

        if let Some(comparison) = &self.comparison {
            root.push_attribute(("Comparison", comparison.to_string().as_ref()));
        }
        writer.write_event(Event::Start(root))?;

        if let Some(authn_context_class_refs) = &self.authn_context_class_refs {
            for authn_context_class_ref in authn_context_class_refs {
                writer.write(authn_context_class_ref.to_xml()?.as_bytes())?;
            }
        } else if let Some(authn_context_decl_refs) = &self.authn_context_decl_refs {
            for authn_context_decl_ref in authn_context_decl_refs {
                writer.write(authn_context_decl_ref.to_xml()?.as_bytes())?;
            }
        }

        writer.write_event(Event::End(BytesEnd::borrowed(NAME.as_bytes())))?;
        Ok(String::from_utf8(write_buf)?)
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct AuthnContextDeclRef {
    #[serde(rename = "$value")]
    pub value: Option<String>,
}

impl AuthnContextDeclRef {
    fn name() -> &'static str {
        "saml2:AuthnContextDeclRef"
    }

    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        if let Some(value) = &self.value {
            let mut write_buf = Vec::new();
            let mut writer = Writer::new(Cursor::new(&mut write_buf));
            let root = BytesStart::borrowed(Self::name().as_bytes(), Self::name().len());

            writer.write_event(Event::Start(root))?;
            writer.write(value.as_bytes())?;
            writer.write_event(Event::End(BytesEnd::borrowed(Self::name().as_bytes())))?;
            Ok(String::from_utf8(write_buf)?)
        } else {
            Ok(String::new())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "lowercase")]
pub enum AuthnContextComparison {
    Exact,
    Minimum,
    Maximum,
    Better,
}

impl ToString for AuthnContextComparison {
    fn to_string(&self) -> String {
        match self {
            AuthnContextComparison::Exact => "exact",
            AuthnContextComparison::Minimum => "minimum",
            AuthnContextComparison::Maximum => "maximum",
            AuthnContextComparison::Better => "better",
        }
        .to_string()
    }
}
