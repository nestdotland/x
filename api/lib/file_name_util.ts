interface ModuleData {
  name: string;
  version: string;
}

interface ModuleFileData extends ModuleData {
  filePath: string;
}

export const PACKAGE_REGEX = /^(?<name>[\-\w]+)@(?<version>(?:(?:[0-9]+)\.(?:[0-9]+)\.(?:[0-9]+)(?:-(?:[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?)(?:\+(?:[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?)$/

export function getNameData(name: string, parseFilePath?: true): ModuleFileData | void;
export function getNameData(name: string, parseFilePath?: false): ModuleData | void;
export function getNameData(name: string, parseFilePath = true): ModuleData | void {
  const [moduleName, ...fileSegments] = name.slice(1).split("/");
  const filePath = `/${fileSegments.join("/")}`;
  const result = PACKAGE_REGEX.exec(moduleName) as { groups: ModuleData } | null;

  if (!result) return;
  if (!parseFilePath) return result.groups;

  const moduleData = {
    ...result.groups,
    filePath,
  }

  return moduleData as ModuleFileData;
}

export function validateName(name: string, parseFilePath = true) {
  // Hacky, but it's true!
  const data = getNameData(name, parseFilePath as true & false);

  return !!data;
}
