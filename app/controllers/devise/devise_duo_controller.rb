class Devise::DeviseDuoController < DeviseController

  prepend_before_action :find_resource_and_require_password_checked, :only => [
    :GET_verify_duo, :POST_verify_duo
  ]
  prepend_before_action :authenticate_scope!, :only => [
    :GET_enable_duo, :POST_enable_duo,
    :GET_verify_duo_installation,
    :POST_disable_duo
  ]

  skip_before_action :verify_authenticity_token, only: :POST_verify_duo

  include Devise::Controllers::Helpers

  def GET_verify_duo
    @sig_request = Duo::sign_request(DeviseDuo.integration_key, DeviseDuo.secret_key, DeviseDuo.application_secret_key, @resource.email)
    render :verify_duo
  end

  # verify 2fa
  def POST_verify_duo
    authenticated_username = Duo::verify_response(DeviseDuo.integration_key, DeviseDuo.secret_key, DeviseDuo.application_secret_key, params[:sig_response])
    if authenticated_username
      @resource.update_attribute(:last_sign_in_with_duo, DateTime.now)
      remember_device if params[:remember_device].to_i == 1
      if session.delete("#{resource_name}_remember_me") == true && @resource.respond_to?(:remember_me=)
        @resource.remember_me = true
      end
      sign_in(resource_name, @resource)
      set_flash_message(:notice, :signed_in) if is_navigational_format?
      respond_with resource, :location => after_sign_in_path_for(@resource)
    else
      handle_invalid_token :verify_duo, :invalid_token
    end
  end

  # enable 2fa
  def GET_enable_duo
    if !resource.duo_enabled
      render :enable_duo
    else
      set_flash_message(:notice, :already_enabled)
      redirect_to after_duo_enabled_path_for(resource)
    end
  end

  def POST_enable_duo
    resource.update_attribute(:duo_enabled, true)
    set_flash_message(:notice, :enabled)
    redirect_to after_duo_enabled_path_for(resource)
  end

  # Disable 2FA
  def POST_disable_duo
    resource.update_attribute(:duo_enabled, false)
    set_flash_message(:notice, :disabled)
    redirect_to root_path
  end

  private

  def authenticate_scope!
    send(:"authenticate_#{resource_name}!", :force => true)
    self.resource = send("current_#{resource_name}")
    @resource = resource
  end

  def find_resource
    @resource = send("current_#{resource_name}")

    if @resource.nil?
      @resource = resource_class.find_by_id(session["#{resource_name}_id"])
    end
  end

  def find_resource_and_require_password_checked
    find_resource

    if @resource.nil? || session[:"#{resource_name}_password_checked"].to_s != "true"
      redirect_to invalid_resource_path
    end
  end

  protected

  def after_duo_enabled_path_for(resource)
    root_path
  end

  def after_duo_verified_path_for(resource)
    after_duo_enabled_path_for(resource)
  end

  def invalid_resource_path
    root_path
  end

  def handle_invalid_token(view, error_message)
    if @resource.respond_to?(:invalid_duo_attempt!) && @resource.invalid_duo_attempt!
      after_account_is_locked
    else
      set_flash_message(:error, error_message)
      render view
    end
  end

  def after_account_is_locked
    sign_out_and_redirect @resource
  end
end
