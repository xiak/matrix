// jsdom has no top layer. These methods enable component lifecycle tests;
// actual focus containment, inertness and responsive dialogs are browser gates.
if (!HTMLDialogElement.prototype.showModal) {
  Object.defineProperties(HTMLDialogElement.prototype, {
    showModal: { configurable: true, value(this: HTMLDialogElement) { this.setAttribute("open", ""); } },
    close: { configurable: true, value(this: HTMLDialogElement) { this.removeAttribute("open"); } }
  });
}
