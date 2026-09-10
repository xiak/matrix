"use client";

import { useEffect, useRef, type FormEventHandler, type ReactNode, type Ref } from "react";
import { Steps } from "../steps/Steps";
import styles from "./Wizard.module.css";

/** Page-level workflow chrome. Drafts, validation, permissions and persistence belong to the feature. */
export function Wizard({ label, steps, currentStep, onStepChange, title, description, progressLabel, busy, completed, formRef, onSubmit, children, actions, hint }: {
  label: string; steps: readonly { id: string; label: string }[]; currentStep: number; onStepChange(index: number): void;
  title: string; description?: string; progressLabel?: string; busy?: boolean; completed?: boolean;
  formRef?: Ref<HTMLFormElement>; onSubmit: FormEventHandler<HTMLFormElement>;
  children: ReactNode; actions: ReactNode; hint?: ReactNode;
}) {
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => { heading.current?.focus(); heading.current?.scrollIntoView?.({ block: "nearest" }); }, [currentStep, completed]);
  return <div className={styles.wizard}>
    {!completed ? <div className={styles.stepsBar}><Steps label={label} items={steps} current={currentStep} onChange={onStepChange} disabled={busy} /></div> : null}
    <form ref={formRef} noValidate onSubmit={onSubmit} aria-label={label} aria-busy={busy}>
      <fieldset className={styles.body} disabled={busy}>
        <div className={styles.heading} data-completed={completed || undefined}><div><h2 ref={heading} tabIndex={-1}>{title}</h2>{description ? <p>{description}</p> : null}</div>{progressLabel ? <span>{progressLabel}</span> : null}</div>
        {children}
      </fieldset>
      <footer className={styles.footer}>{hint ? <span className={styles.hint}>{hint}</span> : null}<div className={styles.actions}>{actions}</div></footer>
    </form>
  </div>;
}
