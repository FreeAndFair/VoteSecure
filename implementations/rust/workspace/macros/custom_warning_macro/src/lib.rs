// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Custom warnings macro

#![cfg_attr(feature = "on", feature(proc_macro_diagnostic, proc_macro_span))]

use cfg_if::cfg_if;

use proc_macro::TokenStream;

cfg_if! {
    if #[cfg(feature = "on")] {

        use proc_macro::Diagnostic;
        use syn::{parse_macro_input, LitStr};

        /// Generates a custom compiler warning with a given message.
        ///
        /// # Examples
        ///
        /// Add `#[crate::warning("Your message")]` above the target code.
        ///
        /// ```ignore
        /// #[crate::warning("Asserts are present in this module.")]
        /// pub mod dkgd;
        /// ```
        #[proc_macro_attribute]
        pub fn warning(attr: TokenStream, item: TokenStream) -> TokenStream {
            let warning_message = parse_macro_input!(attr as LitStr);

            // Find the span that covers the item
            let item_clone = item.clone();
            let mut tokens = item_clone.into_iter();

            // Find the span of the first and last tokens in the stream.
            let first_span = tokens.next().map(|tt| tt.span());
            // last() consumes the rest of the iterator, or(first_span) handles single-token items.
            let last_span = tokens.last().map(|tt| tt.span()).or(first_span);

            // If we found spans, join them to cover the whole item.
            // Otherwise, fall back to the annotation.
            let final_span = if let (Some(first), Some(last)) = (first_span, last_span) {
                // join creates a new span that encompasses both. It returns an Option
                // in case the spans are from different files, but that won't happen here.
                first.join(last).unwrap_or(first)
            } else {
                // If the annotated item is empty, just point to the attribute itself.
                proc_macro::Span::call_site()
            };

            Diagnostic::spanned(
                final_span,
                proc_macro::Level::Warning,
                warning_message.value()
            ).emit();

            // Return the original, unmodified item token stream.
            item
        }
    }
    else {
        #[proc_macro_attribute]
        pub fn warning(_attr: TokenStream, item: TokenStream) -> TokenStream {
            item
        }
    }
}
