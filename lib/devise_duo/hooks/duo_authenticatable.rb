Warden::Manager.after_authentication do |user, auth, options|
  if user.respond_to?(:with_duo_authentication?)
    if auth.session(options[:scope])[:with_duo_authentication] = user.with_duo_authentication?(auth.request)
      auth.session(options[:scope])[:id] = user.id
    end
  end
end
