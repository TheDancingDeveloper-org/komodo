use std::collections::{HashMap, HashSet};

use anyhow::Context;
use komodo_client::entities::{
  EnvironmentVar, build::Build, deployment::Deployment, repo::Repo,
  stack::Stack, update::Log,
};

/// Prefix identifying an Infisical interpolation token
/// (`[[infisical://<project-alias>/<environment>/<SECRET_KEY>]]`).
///
/// Kept in sync by hand with `infisical::TOKEN_PREFIX`. The duplication is
/// deliberate — this crate is compiled into Periphery as well as Core, and
/// depending on the `infisical` crate would drag `reqwest` and `tokio` into
/// the Periphery binary for the sake of one string constant.
pub const INFISICAL_TOKEN_PREFIX: &str = "infisical://";

/// Find a live Infisical reference that the secrets map cannot resolve.
///
/// Scans the *input* to the secret-interpolation pass rather than its output,
/// because the two are ambiguous: `svi` renders both an escaped literal
/// (`[[[infisical://x]]]`) and an unresolved reference (`[[infisical://x]]`)
/// as the same `[[infisical://x]]` text. Only the input distinguishes them.
///
/// The `[[` splitting and the leading-`[` escape rule below deliberately
/// mirror `svi::interpolate_variables`; the unit tests pin that correspondence.
fn unresolved_provider_token(
  input: &str,
  secrets: &HashMap<String, String>,
) -> Option<String> {
  let mut split = input.split("[[");
  // Text before the first opener cannot contain a reference.
  split.next();
  for val in split {
    // svi's escape: '[[[x]]]' is the literal '[[x]]', not a reference.
    if val.starts_with('[') {
      continue;
    }
    // No closing tag - svi raises its own NoClosingTags error for this.
    let Some((token, _)) = val.split_once("]]") else {
      continue;
    };
    if token.starts_with(INFISICAL_TOKEN_PREFIX)
      && !secrets.contains_key(token)
    {
      return Some(token.to_string());
    }
  }
  None
}

/// Fail closed on an unresolvable external-provider reference.
///
/// `svi` is called with `fail_on_missing_variable = false`, which leaves an
/// unknown `[[TOKEN]]` in the output *verbatim*. For an ordinary Komodo
/// variable that is a deliberate, harmless passthrough. For a secret-manager
/// reference it is dangerous: without this check a failed lookup would deploy
/// the literal string `[[infisical://apps/prod/DB_PASSWORD]]` as the password,
/// and the deployment would report success.
///
/// Checking here keeps the blast radius tight. Only resources that actually
/// reference a provider token fail; everything else deploys normally even
/// while the provider is unreachable.
fn ensure_provider_tokens_resolvable(
  input: &str,
  secrets: &HashMap<String, String>,
) -> anyhow::Result<()> {
  match unresolved_provider_token(input, secrets) {
    None => Ok(()),
    Some(token) => anyhow::bail!(
      "unresolved secret reference '{token}'. The Infisical secret provider \
       did not supply this key, so it would have been left uninterpolated. \
       Refusing to deploy a literal token in place of a secret value. Check \
       that the provider is enabled and healthy, and that the project alias, \
       environment and key in the reference all exist."
    ),
  }
}

pub struct Interpolator<'a> {
  variables: Option<&'a HashMap<String, String>>,
  secrets: &'a HashMap<String, String>,
  variable_replacers: HashSet<(String, String)>,
  pub secret_replacers: HashSet<(String, String)>,
}

impl<'a> Interpolator<'a> {
  pub fn new(
    variables: Option<&'a HashMap<String, String>>,
    secrets: &'a HashMap<String, String>,
  ) -> Interpolator<'a> {
    Interpolator {
      variables,
      secrets,
      variable_replacers: Default::default(),
      secret_replacers: Default::default(),
    }
  }

  pub fn interpolate_stack(
    &mut self,
    stack: &mut Stack,
  ) -> anyhow::Result<&mut Self> {
    if stack.config.skip_secret_interp {
      return Ok(self);
    }
    self
      .interpolate_string(&mut stack.config.file_contents)?
      .interpolate_string(&mut stack.config.environment)?
      .interpolate_string(&mut stack.config.pre_deploy.command)?
      .interpolate_string(&mut stack.config.post_deploy.command)?
      .interpolate_string(&mut stack.config.compose_cmd_wrapper)?
      .interpolate_extra_args(&mut stack.config.extra_args)?
      .interpolate_extra_args(&mut stack.config.build_extra_args)
  }

  pub fn interpolate_repo(
    &mut self,
    repo: &mut Repo,
  ) -> anyhow::Result<&mut Self> {
    if repo.config.skip_secret_interp {
      return Ok(self);
    }
    self
      .interpolate_string(&mut repo.config.environment)?
      .interpolate_string(&mut repo.config.on_clone.command)?
      .interpolate_string(&mut repo.config.on_pull.command)
  }

  pub fn interpolate_build(
    &mut self,
    build: &mut Build,
  ) -> anyhow::Result<&mut Self> {
    if build.config.skip_secret_interp {
      return Ok(self);
    }
    self
      .interpolate_string(&mut build.config.build_args)?
      .interpolate_string(&mut build.config.secret_args)?
      .interpolate_string(&mut build.config.labels)?
      .interpolate_string(&mut build.config.pre_build.command)?
      .interpolate_string(&mut build.config.dockerfile)?
      .interpolate_extra_args(&mut build.config.extra_args)
  }

  pub fn interpolate_deployment(
    &mut self,
    deployment: &mut Deployment,
  ) -> anyhow::Result<&mut Self> {
    if deployment.config.skip_secret_interp {
      return Ok(self);
    }
    self
      .interpolate_string(&mut deployment.config.environment)?
      .interpolate_string(&mut deployment.config.ports)?
      .interpolate_string(&mut deployment.config.volumes)?
      .interpolate_string(&mut deployment.config.labels)?
      .interpolate_string(&mut deployment.config.command)?
      .interpolate_extra_args(&mut deployment.config.extra_args)
  }

  pub fn interpolate_string(
    &mut self,
    target: &mut String,
  ) -> anyhow::Result<&mut Self> {
    if target.is_empty() {
      return Ok(self);
    }

    // first pass - variables
    let res = if let Some(variables) = self.variables {
      let (res, more_replacers) = svi::interpolate_variables(
        target,
        variables,
        svi::Interpolator::DoubleBrackets,
        false,
      )
      .with_context(|| {
        format!(
          "failed to interpolate variables into target '{target}'",
        )
      })?;
      self.variable_replacers.extend(more_replacers);
      res
    } else {
      target.to_string()
    };

    // Refuse to proceed if a provider reference cannot be resolved, rather
    // than letting svi pass the raw token through into a deployment.
    ensure_provider_tokens_resolvable(&res, self.secrets)?;

    // second pass - secrets
    let (res, more_replacers) = svi::interpolate_variables(
      &res,
      self.secrets,
      svi::Interpolator::DoubleBrackets,
      false,
    )
    .with_context(|| {
      format!("failed to interpolate secrets into target '{target}'",)
    })?;
    self.secret_replacers.extend(more_replacers);

    // Set with result
    *target = res;

    Ok(self)
  }

  pub fn interpolate_extra_args(
    &mut self,
    extra_args: &mut Vec<String>,
  ) -> anyhow::Result<&mut Self> {
    for arg in extra_args {
      self
        .interpolate_string(arg)
        .context("failed interpolation into extra arg")?;
    }
    Ok(self)
  }

  pub fn interpolate_env_vars(
    &mut self,
    env_vars: &mut Vec<EnvironmentVar>,
  ) -> anyhow::Result<&mut Self> {
    for var in env_vars {
      self
        .interpolate_string(&mut var.value)
        .context("failed interpolation into variable value")?;
    }
    Ok(self)
  }

  pub fn push_logs(&self, logs: &mut Vec<Log>) {
    // Show which variables / values were interpolated
    if !self.variable_replacers.is_empty() {
      logs.push(Log::simple("Interpolate Variables", self.variable_replacers
        .iter()
        .map(|(value, variable)| format!("<span class=\"text-muted-foreground\">{variable} =></span> {value}"))
        .collect::<Vec<_>>()
        .join("\n")));
    }

    // Only show names of interpolated secrets
    if !self.secret_replacers.is_empty() {
      logs.push(
        Log::simple("Interpolate Secrets",
        self.secret_replacers
          .iter()
          .map(|(_, variable)| format!("<span class=\"text-muted-foreground\">replaced:</span> {variable}"))
          .collect::<Vec<_>>()
          .join("\n"),)
      );
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn interpolate(
    target: &str,
    secrets: &[(&str, &str)],
  ) -> anyhow::Result<String> {
    let secrets: HashMap<String, String> = secrets
      .iter()
      .map(|(k, v)| (k.to_string(), v.to_string()))
      .collect();
    let mut interpolator = Interpolator::new(None, &secrets);
    let mut target = target.to_string();
    interpolator.interpolate_string(&mut target)?;
    Ok(target)
  }

  #[test]
  fn resolves_an_infisical_token() {
    let out = interpolate(
      "DB_PASSWORD=[[infisical://apps/prod/DB_PASSWORD]]",
      &[("infisical://apps/prod/DB_PASSWORD", "hunter2")],
    )
    .expect("should resolve");
    assert_eq!(out, "DB_PASSWORD=hunter2");
  }

  #[test]
  fn refuses_to_pass_through_an_unresolved_infisical_token() {
    // The whole point of the guard: without it, svi leaves the token verbatim
    // and Komodo would deploy the literal string as the password.
    let err = interpolate(
      "DB_PASSWORD=[[infisical://apps/prod/MISSING]]",
      &[],
    )
    .expect_err("must not silently pass through");
    let msg = format!("{err:#}");
    assert!(
      msg.contains("infisical://apps/prod/MISSING"),
      "error should name the offending reference, got: {msg}"
    );
  }

  #[test]
  fn unresolved_ordinary_variable_still_passes_through() {
    // Upstream behaviour must be preserved for non-provider tokens, or this
    // fork would break existing Komodo deployments.
    let out = interpolate("FOO=[[NOT_A_PROVIDER_TOKEN]]", &[])
      .expect("upstream passthrough should be preserved");
    assert_eq!(out, "FOO=[[NOT_A_PROVIDER_TOKEN]]");
  }

  #[test]
  fn escaped_token_is_not_treated_as_a_reference() {
    // '[[[x]]]' is svi's escape and yields the literal '[[x]]'. That output
    // contains the prefix but was never a live reference, so the guard must
    // not fire on it.
    let out =
      interpolate("LITERAL=[[[infisical://apps/prod/KEY]]]", &[])
        .expect("escaped token should be allowed");
    assert_eq!(out, "LITERAL=[[infisical://apps/prod/KEY]]");
  }

  #[test]
  fn resolves_several_references_in_one_string() {
    let out = interpolate(
      "A=[[infisical://apps/prod/A]] B=[[infisical://cicd/prod/B]] C=plain",
      &[
        ("infisical://apps/prod/A", "one"),
        ("infisical://cicd/prod/B", "two"),
      ],
    )
    .expect("should resolve both");
    assert_eq!(out, "A=one B=two C=plain");
  }

  #[test]
  fn one_missing_reference_fails_even_when_others_resolve() {
    let err = interpolate(
      "A=[[infisical://apps/prod/A]] B=[[infisical://apps/prod/MISSING]]",
      &[("infisical://apps/prod/A", "one")],
    )
    .expect_err("a single missing reference must fail the whole target");
    assert!(format!("{err:#}").contains("apps/prod/MISSING"));
  }

  #[test]
  fn escape_does_not_survive_the_variables_pass() {
    // Documents a pre-existing svi/Komodo quirk rather than new behaviour:
    // when a variables map is present, interpolation runs twice, and the
    // first pass already consumes the '[[[x]]]' escape into '[[x]]'. The
    // second pass therefore sees a live reference. Escaping a literal
    // provider token is only reliable on resources with no variables pass.
    // Failing closed is the safe direction for that ambiguity.
    let variables = HashMap::new();
    let secrets = HashMap::new();
    let mut interpolator =
      Interpolator::new(Some(&variables), &secrets);
    let mut target = "L=[[[infisical://apps/prod/KEY]]]".to_string();
    assert!(interpolator.interpolate_string(&mut target).is_err());
  }

  #[test]
  fn untouched_input_without_tokens_is_unchanged() {
    let out = interpolate("PLAIN=value", &[]).expect("should pass");
    assert_eq!(out, "PLAIN=value");
  }
}
