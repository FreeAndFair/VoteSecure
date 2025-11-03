// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Serialization derive macro

use proc_macro::Span;
use proc_macro::TokenStream;
use quote::quote;

use syn::{DeriveInput, parse_macro_input};

/// Derives the `VSerializable` trait for structs.
///
/// This procedural macro automatically generates the implementation of the
/// `VSerializable` trait, providing a default serialization and deserialization
/// logic for structs, as well as a [`std::hash::Hash`] implementation based on said
/// serialization. The leaves of the serialization data structure must implement
/// `VSerializable` manually.
///
/// # Examples
///
/// Add `#[derive(VSerializable)]` to your struct.
///
/// ```ignore
/// use cryptography::VSerializable;
///
/// #[derive(VSerializable)]
/// pub struct KeyPair<C: Context> {
///     pub skey: C::Scalar,
///     pub pkey: PublicKey<C>,
/// }
/// ```
#[proc_macro_derive(VSerializable)]
pub fn vser_derive(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);

    impl_exact(&ast)
}

fn impl_exact(ast: &syn::DeriveInput) -> TokenStream {
    let name = &ast.ident;

    let generics = ast.generics.clone();
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    // These variables will be populated based on the struct type (named or tuple)
    let field_tys: Vec<&syn::Type>;
    let as_tuple_members: proc_macro2::TokenStream;
    let from_tuple_constructor: proc_macro2::TokenStream;

    // Match on the data within the struct.
    match &ast.data {
        syn::Data::Struct(s) => {
            // Match on the type of fields.
            match &s.fields {
                syn::Fields::Named(fields) => {
                    field_tys = fields.named.iter().map(|field| &field.ty).collect();
                    let field_names = fields
                        .named
                        .iter()
                        .map(|field| field.ident.as_ref().unwrap());

                    // For `as_tuple`: access members by name (`&self.x`, `&self.y`)
                    as_tuple_members = quote! { #( &self.#field_names, )* };

                    // For `from_tuple`: construct with named fields (`Self { x: t_0, y: t_1 }`)
                    let field_names = fields
                        .named
                        .iter()
                        .map(|field| field.ident.as_ref().unwrap());
                    let tuple_vars = (0..field_tys.len())
                        .map(|i| syn::Ident::new(&format!("t_{i}"), Span::call_site().into()));
                    from_tuple_constructor = quote! { { #( #field_names: #tuple_vars, )* } };
                }
                syn::Fields::Unnamed(fields) => {
                    field_tys = fields.unnamed.iter().map(|field| &field.ty).collect();
                    let field_indices = (0..field_tys.len()).map(syn::Index::from);

                    // For `as_tuple`: access members by index (`&self.0`, `&self.1`)
                    as_tuple_members = quote! { #( &self.#field_indices, )* };

                    // For `from_tuple`: construct as a tuple struct (`Self(t_0, t_1)`)
                    let tuple_vars = (0..field_tys.len())
                        .map(|i| syn::Ident::new(&format!("t_{i}"), Span::call_site().into()));
                    from_tuple_constructor = quote! { ( #( #tuple_vars, )* ) };
                }
                // Also handle unit structs gracefully, which have no fields.
                syn::Fields::Unit => {
                    field_tys = Vec::new();
                    as_tuple_members = quote! {};
                    from_tuple_constructor = quote! { {} };
                }
            }
        }
        // Keep the panic for enums and unions, which are not supported.
        _ => {
            return quote! { compile_error!("VSerializable can only be derived for structs."); }
                .into();
        }
    };

    // This destructuring logic is now common and depends only on the number of fields.
    let field_count = field_tys.len();
    let tuple_vars = (0..field_count)
        .map(|i| syn::Ident::new(&format!("t_{i}"), Span::call_site().into()))
        .collect::<Vec<_>>();

    // Only generate destructuring if there are fields to destructure.
    let tuple_destructuring = if field_count > 0 {
        quote! { let ( #( #tuple_vars, )* ) = tuple; }
    } else {
        quote! {}
    };

    let generated_as_tuple_impl = quote! {
        impl #impl_generics ::cryptography::utils::serialization::TFTuple for #name #ty_generics #where_clause {
            type TupleRef<'a> where Self: 'a = ( #( &'a #field_tys, )* );
            type Tuple = ( #( #field_tys, )* );

            fn as_tuple<'a>(&'a self) -> Self::TupleRef<'a> {
                ( #as_tuple_members )
            }

            fn from_tuple(tuple: Self::Tuple) -> Self {
                // Destructure the tuple into named variables: `t_0`, `t_1`, ...
                #tuple_destructuring

                // Construct the struct using the destructured tuple parts.
                Self #from_tuple_constructor
            }
        }
    };

    let generated_serializable_impl = quote! {
        impl #impl_generics ::cryptography::utils::serialization::VSerializable for #name #ty_generics #where_clause {
            fn ser(&self) -> Vec<u8> {
                use ::cryptography::utils::serialization::TFTuple;

                let tuple = self.as_tuple();
                tuple.ser()
            }
        }
    };

    let generated_deserializable_impl = quote! {
        impl #impl_generics ::cryptography::utils::serialization::VDeserializable for #name #ty_generics #where_clause {
            fn deser(bytes: &[u8]) -> Result<Self, ::cryptography::utils::error::Error> {
                use ::cryptography::utils::serialization::{TFTuple, VDeserializable};

                let tuple = <Self as TFTuple>::Tuple::deser(bytes)?;

                Ok(Self::from_tuple(tuple))
            }
        }
    };

    let generated_hash_impl = quote! {
        impl #impl_generics std::hash::Hash for #name #ty_generics #where_clause {
            fn hash<H>(&self, h: &mut H) where H: std::hash::Hasher {
                use ::cryptography::utils::serialization::variable::VSerializable;

                let bytes = self.ser();

                h.write(&bytes)
            }
        }
    };

    let generated = quote! {
        #generated_as_tuple_impl
        #generated_serializable_impl
        #generated_deserializable_impl
        #generated_hash_impl
    };
    generated.into()
}
